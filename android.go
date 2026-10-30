package dash

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/itchio/arkive/zip"
)

const (
	// Replaces MaxProbeBytes for packages: one whose central directory is out
	// of reach can't be identified at all.
	apkProbeBytes int64 = 16 << 20
	apkMaxEntry   int64 = 8 << 20

	apkSigBlockMagic = "APK Sig Block 42"

	apkSigV2  uint32 = 0x7109871a
	apkSigV3  uint32 = 0xf05368c0
	apkSigV31 uint32 = 0x1b93ad61
)

// androidDetector identifies Android application packages. An APK is one file
// that the system installs, so it stays a single candidate no matter what it
// holds. A .apk with no root AndroidManifest.xml is not a candidate. One whose
// manifest can't be read still is, with only the facts the zip gave up.
type androidDetector struct{}

func (androidDetector) detect(s *scan) error {
	for _, index := range s.filesWithSuffix(".apk") {
		raw, size, err := s.openRaw(index)
		if err != nil {
			s.logf("Could not open APK: %v", err)
			continue
		}
		info, engine := probeAPK(newProbeReader(raw, size, newProbeBudget(apkProbeBytes)))
		if info == nil {
			continue
		}
		c := s.addFileCandidate(index, FlavorAndroid, engine)
		c.AndroidInfo = info
		if info.Split != "" {
			c.Helper = "android"
		}
	}
	return nil
}

func probeAPK(r *probeReader) (*AndroidInfo, *EngineInfo) {
	zr := openZip(r)
	if zr == nil {
		return nil, nil
	}
	entry := zipEntry(zr, "AndroidManifest.xml", true)
	if entry == nil {
		return nil, nil
	}
	info := parseAndroidManifest(zipReadEntry(entry, apkMaxEntry))
	if info == nil {
		info = &AndroidInfo{}
	}

	abis := make(map[string]bool)
	var engine *EngineInfo
	for _, f := range zr.File {
		name := zipEntryPath(f.Name)
		if parts := strings.Split(name, "/"); len(parts) == 3 && parts[0] == "lib" && strings.HasSuffix(parts[2], ".so") {
			abis[parts[1]] = true
		}
		if engine == nil {
			if e, ok := apkEngineFiles[name]; ok {
				engine = &EngineInfo{Engine: e}
			} else if e, ok := apkEngineLibraries[path.Base(name)]; ok && strings.HasPrefix(name, "lib/") {
				engine = &EngineInfo{Engine: e}
			}
		}
	}
	for abi := range abis {
		info.ABIs = append(info.ABIs, abi)
	}
	slices.Sort(info.ABIs)

	info.Signer = apkSigner(r, zr)
	return info, engine
}

var apkEngineLibraries = map[string]Engine{
	"libunity.so":         EngineUnity,
	"libgodot_android.so": EngineGodot,
	"libUE4.so":           EngineUnreal,
	"libUnreal.so":        EngineUnreal,
	"libyoyo.so":          EngineGameMaker,
	"librenpython.so":     EngineRenpy,
	"liblove.so":          EngineLove,
	"libgdx.so":           EngineLibGDX,
	"libflutter.so":       EngineFlutter,
}

var apkEngineFiles = map[string]Engine{
	"assets/www/cordova.js": EngineCordova,
}

// apkSigner reads the newest signature scheme present. Schemes v2 and up live
// in the APK Signing Block, outside any zip entry. Tools that resign modded
// packages with jarsigner leave only v1, a PKCS#7 file under META-INF.
func apkSigner(r *probeReader, zr *zip.Reader) *AndroidSigner {
	var signer *AndroidSigner
	v1 := apkV1SignatureFile(zr)
	schemes := []string{}
	if v1 != nil {
		schemes = append(schemes, "v1")
	}

	block := apkSigningBlock(r)
	var newest []byte
	for _, scheme := range []struct {
		id   uint32
		name string
	}{{apkSigV2, "v2"}, {apkSigV3, "v3"}, {apkSigV31, "v3.1"}} {
		if value := block[scheme.id]; value != nil {
			schemes = append(schemes, scheme.name)
			newest = value
		}
	}

	if der := apkBlockCertificate(newest); der != nil {
		signer = newAndroidSigner(der)
	} else if v1 != nil {
		if der := pkcs7Certificate(zipReadEntry(v1, apkMaxEntry)); der != nil {
			signer = newAndroidSigner(der)
		}
	}
	if len(schemes) == 0 {
		return nil
	}
	if signer == nil {
		signer = &AndroidSigner{}
	}
	signer.Schemes = schemes
	return signer
}

func apkV1SignatureFile(zr *zip.Reader) *zip.File {
	for _, f := range zr.File {
		dir, base := path.Split(zipEntryPath(f.Name))
		if dir != "META-INF/" {
			continue
		}
		switch strings.ToUpper(path.Ext(base)) {
		case ".RSA", ".DSA", ".EC":
			return f
		}
	}
	return nil
}

func newAndroidSigner(der []byte) *AndroidSigner {
	sum := sha256.Sum256(der)
	signer := &AndroidSigner{Sha256: hex.EncodeToString(sum[:])}
	// the fingerprint is what identifies a signer, so a certificate Go
	// refuses to parse still gets one
	if cert, err := x509.ParseCertificate(der); err == nil {
		signer.Subject = cert.Subject.String()
		signer.Debug = cert.Subject.CommonName == "Android Debug"
	}
	return signer
}

// apkSigningBlock returns the block's id-value pairs. The block ends right
// before the central directory with its size and magic.
func apkSigningBlock(r *probeReader) map[uint32][]byte {
	tail := r.readTail(int(min(r.size, 22+0xffff)))
	eocd := bytes.LastIndex(tail, []byte("PK\x05\x06"))
	if eocd < 0 || eocd+20 > len(tail) {
		return nil
	}
	directory := int64(binary.LittleEndian.Uint32(tail[eocd+16:]))
	footer := r.readAt(directory-24, 24)
	if footer == nil || string(footer[8:]) != apkSigBlockMagic {
		return nil
	}
	size := binary.LittleEndian.Uint64(footer)
	if size < 24 || size > uint64(apkProbeBytes) {
		return nil
	}
	// the size excludes the copy of itself at the start of the block
	data := r.readAt(directory-int64(size)-8, int(size)-24+8)
	if data == nil {
		return nil
	}
	pairs := make(map[uint32][]byte)
	for rest := data[8:]; len(rest) >= 12; {
		length := binary.LittleEndian.Uint64(rest)
		if length < 4 || length > uint64(len(rest)-8) {
			break
		}
		// the system takes the first pair with an id
		id := binary.LittleEndian.Uint32(rest[8:])
		if _, seen := pairs[id]; !seen {
			pairs[id] = rest[12 : 8+length]
		}
		rest = rest[8+length:]
	}
	return pairs
}

// apkBlockCertificate walks signers > signer > signed data, then past the
// digests to certificates. v2 and v3 agree up to there. The first certificate
// is the signer's: rotation history is kept elsewhere.
func apkBlockCertificate(value []byte) []byte {
	signers, _ := lengthPrefixed(value)
	signer, _ := lengthPrefixed(signers)
	signed, _ := lengthPrefixed(signer)
	_, afterDigests := lengthPrefixed(signed)
	certificates, _ := lengthPrefixed(afterDigests)
	cert, _ := lengthPrefixed(certificates)
	if len(cert) == 0 {
		return nil
	}
	return cert
}

func lengthPrefixed(b []byte) (value, rest []byte) {
	if len(b) < 4 {
		return nil, nil
	}
	n := uint64(binary.LittleEndian.Uint32(b))
	if n > uint64(len(b)-4) {
		return nil, nil
	}
	return b[4 : 4+n], b[4+n:]
}

// pkcs7Certificate returns the first certificate of a PKCS#7 SignedData.
func pkcs7Certificate(data []byte) []byte {
	var content struct {
		Type   asn1.ObjectIdentifier
		Signed asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(data, &content); err != nil {
		return nil
	}
	var signed struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue
	}
	if _, err := asn1.Unmarshal(content.Signed.Bytes, &signed); err != nil {
		return nil
	}
	if signed.Certificates.Class != asn1.ClassContextSpecific || signed.Certificates.Tag != 0 {
		return nil
	}
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(signed.Certificates.Bytes, &first); err != nil {
		return nil
	}
	return first.FullBytes
}

// androidAttr names a manifest attribute. Shrinkers rename or drop the string,
// so like the system this goes by resource id, falling back on the name for
// the attributes that have none.
type androidAttr struct {
	id   uint32
	name string
}

var (
	attrPackage            = androidAttr{0, "package"}
	attrSplit              = androidAttr{0, "split"}
	attrName               = androidAttr{0x01010003, "name"}
	attrEnabled            = androidAttr{0x0101000e, "enabled"}
	attrValue              = androidAttr{0x01010024, "value"}
	attrDebuggable         = androidAttr{0x0101000f, "debuggable"}
	attrScreenOrientation  = androidAttr{0x0101001e, "screenOrientation"}
	attrTargetActivity     = androidAttr{0x01010202, "targetActivity"}
	attrMinSdkVersion      = androidAttr{0x0101020c, "minSdkVersion"}
	attrVersionCode        = androidAttr{0x0101021b, "versionCode"}
	attrVersionName        = androidAttr{0x0101021c, "versionName"}
	attrTargetSdkVersion   = androidAttr{0x01010270, "targetSdkVersion"}
	attrGlEsVersion        = androidAttr{0x01010281, "glEsVersion"}
	attrRequired           = androidAttr{0x0101028e, "required"}
	attrVersionCodeMajor   = androidAttr{0x01010576, "versionCodeMajor"}
	attrIsSplitRequired    = androidAttr{0x01010591, "isSplitRequired"}
	attrRequiredSplitTypes = androidAttr{0x0101064e, "requiredSplitTypes"}
)

// ordered from most to least preferred launcher entry
var androidLauncherCategories = []string{
	"android.intent.category.LAUNCHER",
	"android.intent.category.LEANBACK_LAUNCHER",
	"com.oculus.intent.category.VR",
}

var androidOrientations = map[uint32]string{
	0: "landscape", 1: "portrait", 2: "user", 3: "behind", 4: "sensor",
	5: "nosensor", 6: "sensorLandscape", 7: "sensorPortrait",
	8: "reverseLandscape", 9: "reversePortrait", 10: "fullSensor",
	11: "userLandscape", 12: "userPortrait", 13: "fullUser", 14: "locked",
}

func parseAndroidManifest(data []byte) *AndroidInfo {
	root := parseAXML(data)
	if root == nil {
		return nil
	}
	info := &AndroidInfo{
		Package:     root.attr(attrPackage).text(),
		Split:       root.attr(attrSplit).text(),
		VersionName: root.attr(attrVersionName).text(),
		VersionCode: int64(root.attr(attrVersionCodeMajor).integer())<<32 | int64(root.attr(attrVersionCode).integer()),
	}
	var gles uint32
	for _, c := range root.children {
		switch c.name {
		case "uses-sdk":
			info.MinSdk = int(c.attr(attrMinSdkVersion).integer())
			info.TargetSdk = int(c.attr(attrTargetSdkVersion).integer())
		case "uses-permission", "uses-permission-sdk-23":
			if name := c.attr(attrName).text(); name != "" {
				info.Permissions = append(info.Permissions, name)
			}
		case "uses-feature":
			name := c.attr(attrName).text()
			required := c.attr(attrRequired).boolean(true)
			switch {
			case name == "":
				if v := c.attr(attrGlEsVersion).integer(); required && v > gles {
					gles = v
				}
			case required:
				info.RequiredFeatures = append(info.RequiredFeatures, name)
			default:
				info.OptionalFeatures = append(info.OptionalFeatures, name)
			}
		case "application":
			info.Debuggable = c.attr(attrDebuggable).boolean(false)
			info.SplitRequired = c.attr(attrIsSplitRequired).boolean(false) || c.attr(attrRequiredSplitTypes).text() != "" || requiresSplits(c)
			info.readLauncher(c)
		}
	}
	if gles != 0 {
		info.GLESVersion = strconv.Itoa(int(gles>>16)) + "." + strconv.Itoa(int(gles&0xffff))
	}
	return info
}

func requiresSplits(app *axmlNode) bool {
	for _, c := range app.children {
		if c.name == "meta-data" && c.attr(attrName).text() == "com.android.vending.splits.required" {
			return c.attr(attrValue).boolean(false)
		}
	}
	return false
}

func (info *AndroidInfo) readLauncher(app *axmlNode) {
	best := len(androidLauncherCategories)
	categories := make(map[string]bool)
	var launcher *axmlNode
	for _, c := range app.children {
		if (c.name != "activity" && c.name != "activity-alias") || !c.attr(attrEnabled).boolean(true) {
			continue
		}
		for _, category := range mainCategories(c) {
			rank := slices.Index(androidLauncherCategories, category)
			if rank < 0 {
				continue
			}
			categories[category] = true
			if rank < best {
				best = rank
				launcher = c
			}
		}
	}
	for _, category := range androidLauncherCategories {
		if categories[category] {
			info.LauncherCategories = append(info.LauncherCategories, category)
		}
	}
	if launcher == nil {
		return
	}
	info.LauncherActivity = qualifyAndroidClass(info.Package, launcher.attr(attrName).text())

	// an alias only points at the activity that declares the orientation
	if target := launcher.attr(attrTargetActivity).text(); launcher.name == "activity-alias" && target != "" {
		qualified := qualifyAndroidClass(info.Package, target)
		for _, c := range app.children {
			if c.name == "activity" && qualifyAndroidClass(info.Package, c.attr(attrName).text()) == qualified {
				launcher = c
				break
			}
		}
	}
	if a := launcher.attr(attrScreenOrientation); a != nil {
		info.Orientation = androidOrientations[a.data]
	}
}

// mainCategories lists the categories of a component's MAIN intent filters.
func mainCategories(component *axmlNode) []string {
	var categories []string
	for _, filter := range component.children {
		if filter.name != "intent-filter" {
			continue
		}
		var main bool
		var found []string
		for _, c := range filter.children {
			name := c.attr(attrName).text()
			switch c.name {
			case "action":
				main = main || name == "android.intent.action.MAIN"
			case "category":
				found = append(found, name)
			}
		}
		if main {
			categories = append(categories, found...)
		}
	}
	return categories
}

func qualifyAndroidClass(pkg, name string) string {
	switch {
	case name == "":
		return ""
	case strings.HasPrefix(name, "."):
		return pkg + name
	case !strings.Contains(name, "."):
		return pkg + "." + name
	}
	return name
}

const (
	axmlChunkFile     = 0x0003
	axmlChunkStrings  = 0x0001
	axmlChunkResMap   = 0x0180
	axmlChunkStartTag = 0x0102
	axmlChunkEndTag   = 0x0103

	axmlTypeReference = 0x01
	axmlTypeString    = 0x03
	axmlTypeIntDec    = 0x10
	axmlTypeIntHex    = 0x11
	axmlTypeBool      = 0x12
)

const axmlNoIndex = 0xffffffff

type axmlNode struct {
	name     string
	attrs    []axmlAttr
	children []*axmlNode
}

type axmlAttr struct {
	name string
	id   uint32
	str  string
	typ  byte
	data uint32
}

func (n *axmlNode) attr(key androidAttr) *axmlAttr {
	for i := range n.attrs {
		a := &n.attrs[i]
		if (key.id != 0 && a.id == key.id) || (a.id == 0 && a.name == key.name) {
			return a
		}
	}
	return nil
}

func (a *axmlAttr) text() string {
	if a == nil {
		return ""
	}
	return a.str
}

// integer also reads numbers written as strings, which is how a non-final
// platform's minSdkVersion can appear. Codenames read as 0.
func (a *axmlAttr) integer() uint32 {
	if a == nil {
		return 0
	}
	switch a.typ {
	case axmlTypeIntDec, axmlTypeIntHex:
		return a.data
	case axmlTypeString:
		n, _ := strconv.ParseUint(a.str, 10, 32)
		return uint32(n)
	}
	return 0
}

func (a *axmlAttr) boolean(fallback bool) bool {
	if a == nil || a.typ != axmlTypeBool {
		return fallback
	}
	return a.data != 0
}

// parseAXML decodes Android binary XML into a tree, returning nil when there
// is no root element. A chunk that doesn't fit ends the walk, keeping what
// came before it: obfuscators damage these files in ways the system tolerates.
func parseAXML(data []byte) *axmlNode {
	if len(data) < 8 || binary.LittleEndian.Uint16(data) != axmlChunkFile {
		return nil
	}
	var pool axmlStrings
	var resources []uint32
	var root *axmlNode
	var stack []*axmlNode

	for p := int(binary.LittleEndian.Uint16(data[2:])); p >= 8 && p+8 <= len(data); {
		kind := binary.LittleEndian.Uint16(data[p:])
		header := int(binary.LittleEndian.Uint16(data[p+2:]))
		size := int64(binary.LittleEndian.Uint32(data[p+4:]))
		if size < 8 || size > int64(len(data)-p) || header < 8 || int64(header) > size {
			break
		}
		chunk := data[p : p+int(size)]
		p += int(size)

		switch kind {
		// the system stops at the first node, so a pool or map after it is a
		// decoy
		case axmlChunkStrings:
			if root == nil {
				pool = parseAXMLStrings(chunk, header)
			}
		case axmlChunkResMap:
			if root == nil {
				for o := header; o+4 <= len(chunk); o += 4 {
					resources = append(resources, binary.LittleEndian.Uint32(chunk[o:]))
				}
			}
		case axmlChunkStartTag:
			node := parseAXMLStart(chunk, header, &pool, resources)
			if len(stack) > 0 {
				top := stack[len(stack)-1]
				top.children = append(top.children, node)
			} else if root == nil {
				root = node
			}
			stack = append(stack, node)
		case axmlChunkEndTag:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return root
}

// parseAXMLStart always returns a node, even an empty one for a damaged tag,
// so that its end tag still pops the right element.
func parseAXMLStart(chunk []byte, header int, pool *axmlStrings, resources []uint32) *axmlNode {
	if len(chunk) < header+20 {
		return &axmlNode{}
	}
	ext := chunk[header:]
	node := &axmlNode{name: pool.get(binary.LittleEndian.Uint32(ext[4:]))}
	start := int(binary.LittleEndian.Uint16(ext[8:]))
	size := int(binary.LittleEndian.Uint16(ext[10:]))
	count := int(binary.LittleEndian.Uint16(ext[12:]))
	if size < 20 {
		return node
	}
	for i := range count {
		o := start + i*size
		if o+20 > len(ext) {
			break
		}
		name := binary.LittleEndian.Uint32(ext[o+4:])
		a := axmlAttr{
			name: pool.get(name),
			typ:  ext[o+15],
			data: binary.LittleEndian.Uint32(ext[o+16:]),
		}
		if int64(name) < int64(len(resources)) {
			a.id = resources[name]
		}
		// the system reads the typed value, the raw one is only a leftover
		// of the source text
		switch raw := binary.LittleEndian.Uint32(ext[o+8:]); {
		case a.typ == axmlTypeString:
			a.str = pool.get(a.data)
		case a.typ != axmlTypeReference && raw != axmlNoIndex:
			a.str = pool.get(raw)
		}
		node.attrs = append(node.attrs, a)
	}
	return node
}

type axmlStrings struct {
	data    []byte
	offsets []byte
	utf8    bool
}

func parseAXMLStrings(chunk []byte, header int) axmlStrings {
	if header < 28 || len(chunk) < header {
		return axmlStrings{}
	}
	count := int64(binary.LittleEndian.Uint32(chunk[8:]))
	flags := binary.LittleEndian.Uint32(chunk[16:])
	start := int64(binary.LittleEndian.Uint32(chunk[20:]))
	if int64(header)+count*4 > int64(len(chunk)) || start > int64(len(chunk)) {
		return axmlStrings{}
	}
	return axmlStrings{
		data:    chunk[start:],
		offsets: chunk[header : int64(header)+count*4],
		utf8:    flags&(1<<8) != 0,
	}
}

func (p *axmlStrings) get(index uint32) string {
	if int64(index)*4+4 > int64(len(p.offsets)) {
		return ""
	}
	o := int64(binary.LittleEndian.Uint32(p.offsets[index*4:]))
	if o >= int64(len(p.data)) {
		return ""
	}
	s := p.data[o:]
	if p.utf8 {
		return axmlUTF8(s)
	}
	return axmlUTF16(s)
}

// A UTF-8 entry leads with its length in UTF-16 units, then in bytes, each
// using a second byte when the high bit of the first is set.
func axmlUTF8(s []byte) string {
	skip := func() int {
		if len(s) == 0 {
			return 0
		}
		n := int(s[0])
		s = s[1:]
		if n&0x80 != 0 {
			if len(s) == 0 {
				return 0
			}
			n = (n&0x7f)<<8 | int(s[0])
			s = s[1:]
		}
		return n
	}
	skip()
	n := skip()
	return string(s[:min(n, len(s))])
}

func axmlUTF16(s []byte) string {
	if len(s) < 2 {
		return ""
	}
	n := int(binary.LittleEndian.Uint16(s))
	s = s[2:]
	if n&0x8000 != 0 {
		if len(s) < 2 {
			return ""
		}
		n = (n&0x7fff)<<16 | int(binary.LittleEndian.Uint16(s))
		s = s[2:]
	}
	n = min(n, len(s)/2)
	units := make([]uint16, n)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(s[i*2:])
	}
	return string(utf16.Decode(units))
}
