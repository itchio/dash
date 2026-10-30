package dash

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/itchio/headway/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var le = binary.LittleEndian

type testAttr struct {
	key androidAttr
	typ byte
	raw string
	num uint32
	// goes in the raw slot while the typed value keeps raw
	decoy string
}

func str(key androidAttr, value string) testAttr {
	return testAttr{key: key, typ: axmlTypeString, raw: value}
}
func num(key androidAttr, value uint32) testAttr {
	return testAttr{key: key, typ: axmlTypeIntDec, num: value}
}
func flag(key androidAttr, value bool) testAttr {
	a := testAttr{key: key, typ: axmlTypeBool}
	if value {
		a.num = 0xffffffff
	}
	return a
}

type testTag struct {
	name     string
	attrs    []testAttr
	children []testTag
}

type axmlBuilder struct {
	strings []string
	index   map[string]uint32
	body    bytes.Buffer
	utf8    bool
}

func (b *axmlBuilder) intern(s string) uint32 {
	if i, ok := b.index[s]; ok {
		return i
	}
	i := uint32(len(b.strings))
	b.strings = append(b.strings, s)
	b.index[s] = i
	return i
}

func (b *axmlBuilder) tag(t testTag) {
	if t.name == "" {
		b.chunk(axmlChunkStartTag, make([]byte, 8))
		b.chunk(axmlChunkEndTag, make([]byte, 16))
		return
	}
	var attrs bytes.Buffer
	for _, a := range t.attrs {
		raw := uint32(axmlNoIndex)
		data := a.num
		if a.typ == axmlTypeString {
			raw = b.intern(a.raw)
			data = raw
			if a.decoy != "" {
				raw = b.intern(a.decoy)
			}
		}
		for _, v := range []uint32{axmlNoIndex, b.intern(a.key.name), raw} {
			attrs.Write(le.AppendUint32(nil, v))
		}
		attrs.Write([]byte{8, 0, 0, a.typ})
		attrs.Write(le.AppendUint32(nil, data))
	}
	ext := le.AppendUint32(nil, axmlNoIndex)
	ext = le.AppendUint32(ext, b.intern(t.name))
	ext = le.AppendUint16(ext, 20)
	ext = le.AppendUint16(ext, 20)
	ext = le.AppendUint16(ext, uint16(len(t.attrs)))
	ext = append(ext, make([]byte, 6)...)
	b.chunk(axmlChunkStartTag, append(make([]byte, 8), append(ext, attrs.Bytes()...)...))
	for _, c := range t.children {
		b.tag(c)
	}
	b.chunk(axmlChunkEndTag, make([]byte, 16))
}

// chunk writes a chunk with a 16 byte header: the two fields after the
// standard 8 bytes are a line number and a comment.
func (b *axmlBuilder) chunk(kind uint16, payload []byte) {
	b.body.Write(axmlChunk(kind, 16, payload))
}

func axmlChunk(kind uint16, header int, payload []byte) []byte {
	out := le.AppendUint16(nil, kind)
	out = le.AppendUint16(out, uint16(header))
	out = le.AppendUint32(out, uint32(8+len(payload)))
	return append(out, payload...)
}

func (b *axmlBuilder) bytes(attrIDs map[string]uint32) []byte {
	// attribute names sit first in the pool, the only strings the resource
	// map covers
	var data, offsets bytes.Buffer
	for _, s := range b.strings {
		offsets.Write(le.AppendUint32(nil, uint32(data.Len())))
		if b.utf8 {
			data.Write([]byte{byte(len(s)), byte(len(s))})
			data.WriteString(s)
			data.WriteByte(0)
		} else {
			units := utf16.Encode([]rune(s))
			data.Write(le.AppendUint16(nil, uint16(len(units))))
			for _, u := range units {
				data.Write(le.AppendUint16(nil, u))
			}
			data.Write([]byte{0, 0})
		}
	}
	var flags uint32
	if b.utf8 {
		flags = 1 << 8
	}
	pool := le.AppendUint32(nil, uint32(len(b.strings)))
	pool = le.AppendUint32(pool, 0)
	pool = le.AppendUint32(pool, flags)
	pool = le.AppendUint32(pool, uint32(28+offsets.Len()))
	pool = le.AppendUint32(pool, 0)
	pool = append(pool, offsets.Bytes()...)
	pool = append(pool, data.Bytes()...)

	var res []byte
	for _, s := range b.strings {
		res = le.AppendUint32(res, attrIDs[s])
	}

	content := axmlChunk(axmlChunkStrings, 28, pool)
	content = append(content, axmlChunk(axmlChunkResMap, 8, res)...)
	content = append(content, b.body.Bytes()...)
	return axmlChunk(axmlChunkFile, 8, content)
}

func buildManifest(root testTag, utf8 bool) []byte {
	b := &axmlBuilder{index: make(map[string]uint32), utf8: utf8}
	ids := make(map[string]uint32)
	var collect func(testTag)
	collect = func(t testTag) {
		for _, a := range t.attrs {
			b.intern(a.key.name)
			ids[a.key.name] = a.key.id
		}
		for _, c := range t.children {
			collect(c)
		}
	}
	collect(root)
	b.tag(root)
	return b.bytes(ids)
}

func filter(action string, categories ...string) testTag {
	t := testTag{name: "intent-filter", children: []testTag{{name: "action", attrs: []testAttr{str(attrName, action)}}}}
	for _, c := range categories {
		t.children = append(t.children, testTag{name: "category", attrs: []testAttr{str(attrName, c)}})
	}
	return t
}

const actionMain = "android.intent.action.MAIN"

var testManifest = testTag{
	name: "manifest",
	attrs: []testAttr{
		str(attrPackage, "com.example.game"),
		num(attrVersionCode, 7),
		num(attrVersionCodeMajor, 2),
		str(attrVersionName, "1.2"),
	},
	children: []testTag{
		{name: "uses-sdk", attrs: []testAttr{num(attrMinSdkVersion, 24), num(attrTargetSdkVersion, 34)}},
		{name: "uses-permission", attrs: []testAttr{str(attrName, "android.permission.INTERNET")}},
		{name: "uses-feature", attrs: []testAttr{num(attrGlEsVersion, 0x30001)}},
		{name: "uses-feature", attrs: []testAttr{str(attrName, "android.hardware.vr.headtracking")}},
		{name: "uses-feature", attrs: []testAttr{str(attrName, "android.hardware.gamepad"), flag(attrRequired, false)}},
		{name: "application", attrs: []testAttr{flag(attrDebuggable, true)}, children: []testTag{
			{name: "activity", attrs: []testAttr{str(attrName, ".Settings")}, children: []testTag{
				filter("android.intent.action.VIEW", "android.intent.category.LAUNCHER"),
			}},
			{name: "activity", attrs: []testAttr{str(attrName, ".Disabled"), flag(attrEnabled, false)}, children: []testTag{
				filter(actionMain, "android.intent.category.LAUNCHER"),
			}},
			{name: "activity", attrs: []testAttr{str(attrName, "Tv"), num(attrScreenOrientation, 1)}, children: []testTag{
				filter(actionMain, "android.intent.category.LEANBACK_LAUNCHER"),
			}},
			{name: "activity", attrs: []testAttr{str(attrName, "org.other.Game"), num(attrScreenOrientation, 6)}},
			{name: "activity-alias", attrs: []testAttr{str(attrName, ".Entry"), str(attrTargetActivity, "org.other.Game")}, children: []testTag{
				filter(actionMain, "android.intent.category.LAUNCHER", "android.intent.category.DEFAULT"),
			}},
		}},
	},
}

func Test_AndroidManifest(t *testing.T) {
	for _, utf8 := range []bool{true, false} {
		info := parseAndroidManifest(buildManifest(testManifest, utf8))
		require.NotNil(t, info)
		assert.Equal(t, "com.example.game", info.Package)
		assert.EqualValues(t, 2<<32|7, info.VersionCode)
		assert.Equal(t, "1.2", info.VersionName)
		assert.Equal(t, 24, info.MinSdk)
		assert.Equal(t, 34, info.TargetSdk)
		assert.Equal(t, "3.1", info.GLESVersion)
		assert.True(t, info.Debuggable)
		assert.Equal(t, []string{"android.permission.INTERNET"}, info.Permissions)
		assert.Equal(t, []string{"android.hardware.vr.headtracking"}, info.RequiredFeatures)
		assert.Equal(t, []string{"android.hardware.gamepad"}, info.OptionalFeatures)
		assert.Equal(t, "com.example.game.Entry", info.LauncherActivity, "launcher beats leanback, alias keeps its own name")
		assert.Equal(t, "sensorLandscape", info.Orientation, "comes from the alias target")
		assert.Equal(t, []string{"android.intent.category.LAUNCHER", "android.intent.category.LEANBACK_LAUNCHER"}, info.LauncherCategories)
	}
}

func Test_AndroidManifestRenamedAttributes(t *testing.T) {
	data := buildManifest(testManifest, true)
	// a shrinker blanks the attribute names, only resource ids are left
	for _, name := range []string{"versionName", "minSdkVersion"} {
		data = bytes.ReplaceAll(data, []byte(name), bytes.Repeat([]byte("x"), len(name)))
	}
	info := parseAndroidManifest(data)
	assert.Equal(t, "1.2", info.VersionName)
	assert.Equal(t, 24, info.MinSdk)
}

func Test_AndroidManifestDamaged(t *testing.T) {
	data := buildManifest(testManifest, false)
	for i := range data {
		parseAndroidManifest(data[:i])
	}
	for i := range data {
		for _, v := range []byte{0x00, 0x7f, 0xff} {
			damaged := bytes.Clone(data)
			damaged[i] = v
			parseAndroidManifest(damaged)
		}
	}
}

func testCertificate(t *testing.T, name string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return der
}

func prefixed(chunks ...[]byte) []byte {
	var out []byte
	for _, c := range chunks {
		out = le.AppendUint32(out, uint32(len(c)))
		out = append(out, c...)
	}
	return out
}

func sigBlockValue(der []byte) []byte {
	digests := prefixed(prefixed([]byte("digest-one")), prefixed([]byte("digest-two")))
	signed := append(prefixed(digests), prefixed(prefixed(der))...)
	return prefixed(prefixed(prefixed(signed)))
}

// insertSigningBlock splices a block in front of the central directory and
// moves the end record's pointer past it.
func insertSigningBlock(archive []byte, pairs map[uint32][]byte) []byte {
	var body []byte
	for id, value := range pairs {
		body = le.AppendUint64(body, uint64(len(value)+4))
		body = le.AppendUint32(body, id)
		body = append(body, value...)
	}
	size := uint64(len(body) + 24)
	block := le.AppendUint64(nil, size)
	block = append(block, body...)
	block = le.AppendUint64(block, size)
	block = append(block, apkSigBlockMagic...)

	eocd := bytes.LastIndex(archive, []byte("PK\x05\x06"))
	directory := le.Uint32(archive[eocd+16:])
	out := bytes.Clone(archive[:directory])
	out = append(out, block...)
	out = append(out, archive[directory:]...)
	le.PutUint32(out[eocd+len(block)+16:], directory+uint32(len(block)))
	return out
}

func zipBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func writeFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), data, 0o644))
}

func probeTestAPK(t *testing.T, data []byte) (*AndroidInfo, *EngineInfo) {
	t.Helper()
	return probeAPK(newProbeReader(bytes.NewReader(data), int64(len(data)), newProbeBudget(apkProbeBytes)))
}

func Test_APKSigner(t *testing.T) {
	manifest := buildManifest(testManifest, true)
	v2 := testCertificate(t, "Android Debug")
	v3 := testCertificate(t, "Newest")

	base := zipBytes(t, map[string][]byte{"AndroidManifest.xml": manifest})

	info, _ := probeTestAPK(t, insertSigningBlock(base, map[uint32][]byte{apkSigV2: sigBlockValue(v2)}))
	require.NotNil(t, info.Signer)
	assert.Equal(t, []string{"v2"}, info.Signer.Schemes)
	assert.Equal(t, newAndroidSigner(v2).Sha256, info.Signer.Sha256)
	assert.Contains(t, info.Signer.Subject, "Android Debug")
	assert.True(t, info.Signer.Debug)

	info, _ = probeTestAPK(t, insertSigningBlock(base, map[uint32][]byte{
		apkSigV2: sigBlockValue(v2),
		apkSigV3: sigBlockValue(v3),
	}))
	assert.Equal(t, []string{"v2", "v3"}, info.Signer.Schemes)
	assert.Equal(t, newAndroidSigner(v3).Sha256, info.Signer.Sha256, "newest scheme wins")
	assert.False(t, info.Signer.Debug)

	info, _ = probeTestAPK(t, base)
	assert.Nil(t, info.Signer, "unsigned")
}

func Test_APKSignerV1(t *testing.T) {
	cert := testCertificate(t, "jarsigner")
	signed, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue
		SignerInfos      asn1.RawValue
	}{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
		ContentInfo:      asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: cert},
		SignerInfos:      asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true},
	})
	require.NoError(t, err)
	p7, err := asn1.Marshal(struct {
		Type   asn1.ObjectIdentifier
		Signed asn1.RawValue
	}{
		Type:   asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		Signed: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signed},
	})
	require.NoError(t, err)

	info, _ := probeTestAPK(t, zipBytes(t, map[string][]byte{
		"AndroidManifest.xml": buildManifest(testManifest, true),
		"META-INF/CERT.RSA":   p7,
	}))
	require.NotNil(t, info.Signer)
	assert.Equal(t, []string{"v1"}, info.Signer.Schemes)
	assert.Equal(t, newAndroidSigner(cert).Sha256, info.Signer.Sha256)
}

func Test_APKDetection(t *testing.T) {
	root := t.TempDir()
	manifest := buildManifest(testManifest, true)
	writeFile(t, root, "builds/game.apk", zipBytes(t, map[string][]byte{
		"AndroidManifest.xml":          manifest,
		"lib/arm64-v8a/libunity.so":    {1},
		"lib/armeabi-v7a/libunity.so":  {1},
		"assets/lib/x86/not-a-lib.so":  {1},
		"lib/arm64-v8a/nested/skip.so": {1},
	}))
	writeFile(t, root, "builds/damaged.apk", zipBytes(t, map[string][]byte{
		"AndroidManifest.xml":   []byte("not binary xml"),
		"assets/www/cordova.js": {1},
	}))
	writeFile(t, root, "builds/renamed.apk", zipBytes(t, map[string][]byte{"readme.txt": {1}}))
	writeFile(t, root, "builds/text.apk", []byte("hello"))
	writeFile(t, root, "game.exe", []byte{})

	targets, err := ScanLaunchTargets(context.Background(), root, ConfigureParams{})
	require.NoError(t, err)
	byPath := make(map[string]LaunchTarget)
	for _, target := range targets {
		byPath[filepath.ToSlash(target.Path)] = target
	}
	require.Len(t, byPath, 2)

	game := byPath["builds/game.apk"]
	assert.Equal(t, FlavorAndroid, game.Flavor)
	assert.Equal(t, EngineUnity, game.Engine.Engine)
	assert.Equal(t, "com.example.game", game.AndroidInfo.Package)
	assert.Equal(t, []string{"arm64-v8a", "armeabi-v7a"}, game.AndroidInfo.ABIs)

	damaged := byPath["builds/damaged.apk"]
	assert.Equal(t, FlavorAndroid, damaged.Flavor)
	assert.Equal(t, EngineCordova, damaged.Engine.Engine)
	assert.Empty(t, damaged.AndroidInfo.Package)
}

func Test_AndroidManifestAdversarial(t *testing.T) {
	permission := str(attrName, "android.permission.READ_SMS")
	permission.decoy = "android.permission.INTERNET"
	info := parseAndroidManifest(buildManifest(testTag{
		name:  "manifest",
		attrs: []testAttr{str(attrPackage, "com.example.game")},
		children: []testTag{
			{}, // damaged tag: its end must not close <manifest>
			{name: "uses-permission", attrs: []testAttr{permission}},
			{name: "application", children: []testTag{
				{name: "meta-data", attrs: []testAttr{str(attrName, "com.android.vending.splits.required"), flag(attrValue, true)}},
			}},
		},
	}, true))
	assert.Equal(t, []string{"android.permission.READ_SMS"}, info.Permissions)
	assert.True(t, info.SplitRequired)
}

func Test_APKSplitIsHelper(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "base.apk", zipBytes(t, map[string][]byte{"AndroidManifest.xml": buildManifest(testManifest, true)}))
	writeFile(t, root, "split_config.arm64_v8a.apk", zipBytes(t, map[string][]byte{"AndroidManifest.xml": buildManifest(testTag{
		name:  "manifest",
		attrs: []testAttr{str(attrPackage, "com.example.game"), str(attrSplit, "config.arm64_v8a")},
	}, true), "padding": make([]byte, 1<<16)}))
	verdict, err := Configure(context.Background(), root, ConfigureParams{})
	require.NoError(t, err)
	candidates := verdict.Filter(&state.Consumer{}, FilterParams{OS: "android"}).Candidates
	require.Len(t, candidates, 1)
	assert.Equal(t, "base.apk", candidates[0].Path)
}

func Test_APKWinsOnAndroid(t *testing.T) {
	apk := zipBytes(t, map[string][]byte{"AndroidManifest.xml": buildManifest(testManifest, true)})

	readme := t.TempDir()
	writeFile(t, readme, "readme.html", []byte("<html></html>"))
	writeFile(t, readme, "android/game.apk", apk)

	love := t.TempDir()
	writeFile(t, love, "game.love", zipBytes(t, map[string][]byte{"main.lua": []byte("-- game")}))
	writeFile(t, love, "game.apk", apk)

	for _, root := range []string{readme, love} {
		verdict, err := Configure(context.Background(), root, ConfigureParams{})
		require.NoError(t, err)
		require.Len(t, verdict.Candidates, 2)
		candidates := verdict.Filter(&state.Consumer{}, FilterParams{OS: "android"}).Candidates
		require.Len(t, candidates, 1)
		assert.Equal(t, FlavorAndroid, candidates[0].Flavor)
	}
}

func Test_APKFilter(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "game.apk", zipBytes(t, map[string][]byte{"AndroidManifest.xml": buildManifest(testManifest, true)}))
	verdict, err := Configure(context.Background(), root, ConfigureParams{})
	require.NoError(t, err)
	require.Len(t, verdict.Candidates, 1)

	consumer := &state.Consumer{}
	assert.Len(t, verdict.Filter(consumer, FilterParams{OS: "android", Arch: "arm64"}).Candidates, 1)
	for _, os := range []string{"windows", "linux", "darwin"} {
		assert.Empty(t, verdict.Filter(consumer, FilterParams{OS: os, Arch: "amd64"}).Candidates, os)
	}
}
