import std/[strutils]
import ./aes
import ./galois
import std/os

# Helpers
proc hexToBytes(h: string): seq[byte] =
  assert h.len mod 2 == 0
  result = newSeq[byte](h.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(h[2*i .. 2*i+1]))

proc joinHex(parts: varargs[string]): string = parts.join("")

proc assertEqHex(actual: openArray[byte], expectedHex: string) =
  let a = hexDigest(actual)
  doAssert a.toLowerAscii() == expectedHex.toLowerAscii(), "expected " & expectedHex & ", got " & a

# NIST SP 800-38A Test Vectors (AES-128)
# ECB F.1
proc testEcb128() =
  let key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
  var ecb = newAesEcbCtx(key)
  let pt = hexToBytes(joinHex(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710"))
  let ct = ecb.encrypt(pt)
  assertEqHex(ct, joinHex(
    "3ad77bb40d7a3660a89ecaf32466ef97",
    "f5d3d58503b9699de785895a96fdbaaf",
    "43b1cd7f598ece23881b00e3ed030688",
    "7b0c785e27e8ad3f8223207104725dd4"))
  let rt = ecb.decrypt(ct)
  doAssert rt == pt

# CBC F.2
proc testCbc128() =
  let key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
  let iv  = hexToBytes("000102030405060708090a0b0c0d0e0f")
  var cbc = newAesCbcCtx(key, iv)
  let pt = hexToBytes(joinHex(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710"))
  let ct = cbc.encrypt(pt)
  assertEqHex(ct, joinHex(
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7"))
  var cbc2 = newAesCbcCtx(key, iv)
  let rt = cbc2.decrypt(ct)
  doAssert rt == pt

# CTR F.5 (initial counter block = f0..f7 f8..ff)
proc testCtr128() =
  let key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
  let nonce = hexToBytes("f0f1f2f3f4f5f6f7")
  let init  = hexToBytes("f8f9fafbfcfdfeff")
  var ctr = newAesCtrCtx(key, nonce, init)
  let pt = hexToBytes(joinHex(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710"))
  let ct = ctr.encrypt(pt)
  assertEqHex(ct, joinHex(
    "874d6191b620e3261bef6864990db6ce",
    "9806f66b7970fdff8617187bb9fffdff",
    "5ae4df3edbd5d35e5b4f09020db03eab",
    "1e031dda2fbe03d1792170a0f3009cee"))
  var ctr2 = newAesCtrCtx(key, nonce, init)
  let rt = ctr2.decrypt(ct)
  doAssert rt == pt

when isMainModule:
  testEcb128()
  testCbc128()
  testCtr128()
  # AES-192 ECB
  proc testEcb192() =
    let key = hexToBytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
    var ecb = newAesEcbCtx(key)
    let pt = hexToBytes(joinHex(
      "6bc1bee22e409f96e93d7e117393172a",
      "ae2d8a571e03ac9c9eb76fac45af8e51",
      "30c81c46a35ce411e5fbc1191a0a52ef",
      "f69f2445df4f9b17ad2b417be66c3710"))
    let ct = ecb.encrypt(pt)
    assertEqHex(ct, joinHex(
      "bd334f1d6e45f25ff712a214571fa5cc",
      "974104846d0ad3ad7734ecb3ecee4eef",
      "ef7afd2270e2e60adce0ba2face6444e",
      "9a4b41ba738d6c72fb16691603c18e0e"))
    let rt = ecb.decrypt(ct)
    doAssert rt == pt
  testEcb192()
  # AES-256 ECB
  proc testEcb256() =
    let key = hexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    var ecb = newAesEcbCtx(key)
    let pt = hexToBytes(joinHex(
      "6bc1bee22e409f96e93d7e117393172a",
      "ae2d8a571e03ac9c9eb76fac45af8e51",
      "30c81c46a35ce411e5fbc1191a0a52ef",
      "f69f2445df4f9b17ad2b417be66c3710"))
    let ct = ecb.encrypt(pt)
    assertEqHex(ct, joinHex(
      "f3eed1bdb5d2a03c064b5a7e3db181f8",
      "591ccb10d410ed26dc5ba74a31362870",
      "b6ed21b99ca6f4f9f153e7b1beafed1d",
      "23304b7a39f9f3ff067d8d8f9e24ecc7"))
    let rt = ecb.decrypt(ct)
    doAssert rt == pt
  testEcb256()
  # AES-192 CBC
  proc testCbc192() =
    let key = hexToBytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
    let iv  = hexToBytes("000102030405060708090a0b0c0d0e0f")
    var cbc = newAesCbcCtx(key, iv)
    let pt = hexToBytes(joinHex(
      "6bc1bee22e409f96e93d7e117393172a",
      "ae2d8a571e03ac9c9eb76fac45af8e51",
      "30c81c46a35ce411e5fbc1191a0a52ef",
      "f69f2445df4f9b17ad2b417be66c3710"))
    let ct = cbc.encrypt(pt)
    assertEqHex(ct, joinHex(
      "4f021db243bc633d7178183a9fa071e8",
      "b4d9ada9ad7dedf4e5e738763f69145a",
      "571b242012fb7ae07fa9baac3df102e0",
      "08b0e27988598881d920a9e64f5615cd"))
    var cbc2 = newAesCbcCtx(key, iv)
    let rt = cbc2.decrypt(ct)
    doAssert rt == pt
  testCbc192()
  # AES-256 CBC
  proc testCbc256() =
    let key = hexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    let iv  = hexToBytes("000102030405060708090a0b0c0d0e0f")
    var cbc = newAesCbcCtx(key, iv)
    let pt = hexToBytes(joinHex(
      "6bc1bee22e409f96e93d7e117393172a",
      "ae2d8a571e03ac9c9eb76fac45af8e51",
      "30c81c46a35ce411e5fbc1191a0a52ef",
      "f69f2445df4f9b17ad2b417be66c3710"))
    let ct = cbc.encrypt(pt)
    assertEqHex(ct, joinHex(
      "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
      "9cfc4e967edb808d679f777bc6702c7d",
      "39f23369a9d9bacfa530e26304231461",
      "b2eb05e2c39be9fcda6c19078c6a9d1b"))
    var cbc2 = newAesCbcCtx(key, iv)
    let rt = cbc2.decrypt(ct)
    doAssert rt == pt
  testCbc256()
  # AES-192 CTR
  proc testCtr192() =
    let key = hexToBytes("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
    let nonce = hexToBytes("f0f1f2f3f4f5f6f7")
    let init  = hexToBytes("f8f9fafbfcfdfeff")
    var ctr = newAesCtrCtx(key, nonce, init)
    let pt = hexToBytes(joinHex(
      "6bc1bee22e409f96e93d7e117393172a",
      "ae2d8a571e03ac9c9eb76fac45af8e51",
      "30c81c46a35ce411e5fbc1191a0a52ef",
      "f69f2445df4f9b17ad2b417be66c3710"))
    let ct = ctr.encrypt(pt)
    assertEqHex(ct, joinHex(
      "1abc932417521ca24f2b0459fe7e6e0b",
      "090339ec0aa6faefd5ccc2c6f4ce8e94",
      "1e36b26bd1ebc670d1bd1d665620abf7",
      "4f78a7f6d29809585a97daec58c6b050"))
    var ctr2 = newAesCtrCtx(key, nonce, init)
    let rt = ctr2.decrypt(ct)
    doAssert rt == pt
  testCtr192()
  # AES-256 CTR
  proc testCtr256() =
    let key = hexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    let nonce = hexToBytes("f0f1f2f3f4f5f6f7")
    let init  = hexToBytes("f8f9fafbfcfdfeff")
    var ctr = newAesCtrCtx(key, nonce, init)
    let pt = hexToBytes(joinHex(
      "6bc1bee22e409f96e93d7e117393172a",
      "ae2d8a571e03ac9c9eb76fac45af8e51",
      "30c81c46a35ce411e5fbc1191a0a52ef",
      "f69f2445df4f9b17ad2b417be66c3710"))
    let ct = ctr.encrypt(pt)
    assertEqHex(ct, joinHex(
      "601ec313775789a5b7a7f504bbf3d228",
      "f443e3ca4d62b59aca84e990cacaf5c5",
      "2b0930daa23de94ce87017ba2d84988d",
      "dfc9c58db67aada613c2dd08457941a6"))
    var ctr2 = newAesCtrCtx(key, nonce, init)
    let rt = ctr2.decrypt(ct)
    doAssert rt == pt
  testCtr256()
  # AES-GCM tests (common NIST/RFC vectors)
  proc toHexBytes(s: string): seq[byte] = hexToBytes(s)
  proc testGcmEmpty() =
    # Key = 0^128, IV = 0^96, PT = empty, AAD = empty
    let key = hexToBytes("00000000000000000000000000000000")
    let iv  = hexToBytes("000000000000000000000000")
    var gcm = newAesGcmCtx(key, iv)
    let aad = newSeq[byte](0)
    let pt  = newSeq[byte](0)
    let (ct, tag) = gcm.encrypt(aad, pt)
    doAssert ct.len == 0
    var tagHex = ""
    for b in tag: tagHex.add(b.toHex(2).toLowerAscii())
    doAssert tagHex == "58e2fccefa7e3061367f1d57a4e7455a"
  testGcmEmpty()
  proc testGcmSingleZeroBlock() =
    # Key = 0^128, IV = 0^96, PT = 0^128
    let key = hexToBytes("00000000000000000000000000000000")
    let iv  = hexToBytes("000000000000000000000000")
    var gcm = newAesGcmCtx(key, iv)
    let aad = newSeq[byte](0)
    let pt  = hexToBytes("00000000000000000000000000000000")
    let (ct, tag) = gcm.encrypt(aad, pt)
    assertEqHex(ct, "0388dace60b6a392f328c2b971b2fe78")
    var tagHex = ""
    for b in tag: tagHex.add(b.toHex(2).toLowerAscii())
    doAssert tagHex == "ab6e47d42cec13bdf53a67b21257bddf"
    var tagSeq = newSeq[byte](16)
    for i in 0 ..< 16: tagSeq[i] = tag[i]
    let rt = gcm.decrypt(aad, ct, tagSeq)
    doAssert rt == pt
  testGcmSingleZeroBlock()
  # AES-GCM-SIV vectors (RFC 8452 Appendix C) - a couple of cases
  proc testGcmSivEmpty() =
    let key = hexToBytes("01000000000000000000000000000000")
    let nonce = hexToBytes("030000000000000000000000")
    var g = newAesGcmSivCtx(key, nonce)
    let aad = newSeq[byte](0)
    let pt  = newSeq[byte](0)
    let (ct, tag) = g.encrypt(aad, pt)
    doAssert ct.len == 0
    var tagHex = ""
    for b in tag: tagHex.add(b.toHex(2).toLowerAscii())
    doAssert tagHex == "dc20e2d83f25705bb49e439eca56de25"
  testGcmSivEmpty()

  proc testGcmSivOneBlock() =
    let key = hexToBytes("01000000000000000000000000000000")
    let nonce = hexToBytes("030000000000000000000000")
    var g = newAesGcmSivCtx(key, nonce)
    let aad = newSeq[byte](0)
    let pt  = hexToBytes("01000000000000000000000000000000")
    let (ct, tag) = g.encrypt(aad, pt)
    var tagHex = ""
    for b in tag: tagHex.add(b.toHex(2).toLowerAscii())
    doAssert tagHex == "303aaf90f6fe21199c6068577437a0c4"
    assertEqHex(ct, "743f7c8077ab25f8624e2e948579cf77")
    var tagSeq = newSeq[byte](16)
    for i in 0 ..< 16: tagSeq[i] = tag[i]
    let rt = g.decrypt(aad, ct, tagSeq)
    doAssert rt == pt
  # Verify per-nonce subkeys per RFC
  block:
    let key = hexToBytes("01000000000000000000000000000000")
    let nonce = hexToBytes("030000000000000000000000")
    let (encKey, authKey) = deriveGcmSivKeys(key, nonce)
    doAssert hexDigest(authKey) == "d9b360279694941ac5dbc6987ada7377"
    doAssert hexDigest(encKey) == "4004a0dcd862f2a57360219d2d44ef6c"
  testGcmSivOneBlock()
  # AES-256 GCM-SIV — key = 0100.., various PT/AAD
  proc tagHexStr(tag: array[16, byte]): string =
    var s = ""
    for b in tag: s.add(b.toHex(2).toLowerAscii())
    s

  proc testGcmSiv256_Empty_NoAAD() =
    let key = hexToBytes(joinHex(
      "01000000000000000000000000000000",
      "00000000000000000000000000000000"))
    let nonce = hexToBytes("030000000000000000000000")
    var g = newAesGcmSivCtx(key, nonce)
    let aad = newSeq[byte](0)
    let pt  = newSeq[byte](0)
    let (ct, tag) = g.encrypt(aad, pt)
    doAssert ct.len == 0
    doAssert tagHexStr(tag) == "07f5f4169bbf55a8400cd47ea6fd400f"
  testGcmSiv256_Empty_NoAAD()

  proc testGcmSiv256_8_NoAAD() =
    let key = hexToBytes(joinHex(
      "01000000000000000000000000000000",
      "00000000000000000000000000000000"))
    let nonce = hexToBytes("030000000000000000000000")
    var g = newAesGcmSivCtx(key, nonce)
    let aad = newSeq[byte](0)
    let pt  = hexToBytes("0100000000000000")
    let (ct, tag) = g.encrypt(aad, pt)
    assertEqHex(ct, "c2ef328e5c71c83b")
    doAssert tagHexStr(tag) == "843122130f7364b761e0b97427e3df28"
  testGcmSiv256_8_NoAAD()

  proc testGcmSiv256_16_NoAAD() =
    let key = hexToBytes(joinHex(
      "01000000000000000000000000000000",
      "00000000000000000000000000000000"))
    let nonce = hexToBytes("030000000000000000000000")
    var g = newAesGcmSivCtx(key, nonce)
    let aad = newSeq[byte](0)
    let pt  = hexToBytes("01000000000000000000000000000000")
    let (ct, tag) = g.encrypt(aad, pt)
    assertEqHex(ct, "85a01b63025ba19b7fd3ddfc033b3e76")
    doAssert tagHexStr(tag) == "c9eac6fa700942702e90862383c6c366"
  testGcmSiv256_16_NoAAD()

  proc testGcmSiv256_16_AAD1() =
    let key = hexToBytes(joinHex(
      "01000000000000000000000000000000",
      "00000000000000000000000000000000"))
    let nonce = hexToBytes("030000000000000000000000")
    var g = newAesGcmSivCtx(key, nonce)
    let aad = hexToBytes("01")
    let pt  = hexToBytes("02000000000000000000000000000000")
    let (ct, tag) = g.encrypt(aad, pt)
    assertEqHex(ct, "c91545823cc24f17dbb0e9e807d5ec17")
    doAssert tagHexStr(tag) == "b292d28ff61189e8e49f3875ef91aff7"
  testGcmSiv256_16_AAD1()

  proc testGcmSiv256_32_AAD1() =
    let key = hexToBytes(joinHex(
      "01000000000000000000000000000000",
      "00000000000000000000000000000000"))
    let nonce = hexToBytes("030000000000000000000000")
    var g = newAesGcmSivCtx(key, nonce)
    let aad = hexToBytes("01")
    let pt  = hexToBytes(joinHex(
      "02000000000000000000000000000000",
      "03000000000000000000000000000000"))
    let (ct, tag) = g.encrypt(aad, pt)
    assertEqHex(ct, joinHex(
      "07dad364bfc2b9da89116d7bef6daaaf",
      "6f255510aa654f920ac81b94e8bad365"))
    doAssert tagHexStr(tag) == "aea1bad12702e1965604374aab96dbbc"
  testGcmSiv256_32_AAD1()

  proc testGcmSiv256_64_AAD1() =
    let key = hexToBytes(joinHex(
      "01000000000000000000000000000000",
      "00000000000000000000000000000000"))
    let nonce = hexToBytes("030000000000000000000000")
    var g = newAesGcmSivCtx(key, nonce)
    let aad = hexToBytes("01")
    let pt  = hexToBytes(joinHex(
      "02000000000000000000000000000000",
      "03000000000000000000000000000000",
      "04000000000000000000000000000000",
      "05000000000000000000000000000000"))
    let (ct, tag) = g.encrypt(aad, pt)
    assertEqHex(ct, joinHex(
      "67fd45e126bfb9a79930c43aad2d3696",
      "7d3f0e4d217c1e551f59727870beefc9",
      "8cb933a8fce9de887b1e40799988db1f",
      "c3f91880ed405b2dd298318858467c89"))
    doAssert tagHexStr(tag) == "5bde0285037c5de81e5b570a049b62a0"
  testGcmSiv256_64_AAD1()

  proc testGcmSiv256_12_AAD1() =
    let key = hexToBytes(joinHex(
      "01000000000000000000000000000000",
      "00000000000000000000000000000000"))
    let nonce = hexToBytes("030000000000000000000000")
    var g = newAesGcmSivCtx(key, nonce)
    let aad = hexToBytes("01")
    let pt  = hexToBytes("020000000000000000000000")
    let (ct, tag) = g.encrypt(aad, pt)
    assertEqHex(ct, "163d6f9cc1b346cd453a2e4c")
    doAssert tagHexStr(tag) == "c1a4a19ae800941ccdc57cc8413c277f"
  testGcmSiv256_12_AAD1()

  proc testGcmSiv256_4_AAD12() =
    let key = hexToBytes(joinHex(
      "01000000000000000000000000000000",
      "00000000000000000000000000000000"))
    let nonce = hexToBytes("030000000000000000000000")
    var g = newAesGcmSivCtx(key, nonce)
    let aad = hexToBytes("010000000000000000000000")
    let pt  = hexToBytes("02000000")
    let (ct, tag) = g.encrypt(aad, pt)
    assertEqHex(ct, "22b3f4cd")
    doAssert tagHexStr(tag) == "1835e517741dfddccfa07fa4661b74cf"
  testGcmSiv256_4_AAD12()
  # AEAD wrappers quick checks
  block:
    # GCM aead
    let key = hexToBytes("00000000000000000000000000000000")
    let iv  = hexToBytes("000000000000000000000000")
    var gcm = newAesGcmCtx(key, iv)
    let aad = newSeq[byte](0)
    let pt  = hexToBytes("00000000000000000000000000000000")
    let outBuf = gcm.encryptAead(aad, pt)
    # expected ct||tag
    doAssert hexDigest(outBuf) == "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"
    let rt = gcm.decryptAead(aad, outBuf)
    doAssert rt == pt
  block:
    # GCM-SIV aead
    let key = hexToBytes("01000000000000000000000000000000")
    let nonce = hexToBytes("030000000000000000000000")
    var g = newAesGcmSivCtx(key, nonce)
    let aad = newSeq[byte](0)
    let pt  = hexToBytes("01000000000000000000000000000000")
    let outBuf2 = g.encryptAead(aad, pt)
    doAssert hexDigest(outBuf2) == "743f7c8077ab25f8624e2e948579cf77303aaf90f6fe21199c6068577437a0c4"
    let rt2 = g.decryptAead(aad, outBuf2)
    doAssert rt2 == pt
  # Appendix A mulX mapping check
  block:
    let H = hexToBytes("25629347589242761d31f826ba4b757b")
    var Hb: Block128
    for i in 0 ..< 16: Hb[i] = H[15 - i]
    let Hx = mulX_GHASH(Hb)
    doAssert hexDigest(@Hx) == "dcbaa5dd137c188ebb21492c23c9b112"
  # Verify Appendix A mulX_GHASH(ByteReverse(H)) example
  block:
    let H = hexToBytes("25629347589242761d31f826ba4b757b")
    var Hb: Block128
    for i in 0 ..< 16: Hb[i] = H[15 - i]
    let Hx = mulX_GHASH(Hb)
    doAssert hexDigest(@Hx) == "dcbaa5dd137c188ebb21492c23c9b112"
  echo "nist ok"
  # XTS sample vector (from SP 800-38E Example)
  block:
    let k1 = hexToBytes("27182818284590452353602874713526")
    let k2 = hexToBytes("31415926535897932384626433832795")
    var xts = newAesXtsCtx(k1, k2)
    let tweak = hexToBytes("000102030405060708090a0b0c0d0e0f")
    let pt = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let ct = xts.encrypt(tweak, pt)
    assertEqHex(ct, "47fa81638f55184219889d3c28b0ca47a0a026216fcc28cbfbc431d2cf6d12fc")
  # XTS ciphertext stealing (partial last block), AES-128
  block:
    let k1 = hexToBytes("27182818284590452353602874713526")
    let k2 = hexToBytes("31415926535897932384626433832795")
    var xts = newAesXtsCtx(k1, k2)
    let tweak = hexToBytes("000102030405060708090a0b0c0d0e0f")
    let pt = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718") # 24+ bytes (not multiple of 16)
    let ct = xts.encrypt(tweak, pt)
    let rt = xts.decrypt(tweak, ct)
    doAssert rt == pt
    # string helpers
    let ctx2 = newAesXtsCtx("27182818284590452353602874713526", "31415926535897932384626433832795")
    let cth = ctx2.encryptXtsHex("000102030405060708090a0b0c0d0e0f", hexDigest(pt))
    let pth = ctx2.decryptXtsHex("000102030405060708090a0b0c0d0e0f", cth)
    doAssert pth == hexDigest(pt)
  # XTS ciphertext stealing (partial last block), AES-256
  block:
    let k1_256 = hexToBytes("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
    let k2_256 = hexToBytes("9d1a7031d0f8b8fd6f76f4cc14fb85f73c6e0b8a9f6112e6ba0b9d0b6ebe9f9a")
    var xts = newAesXtsCtx(k1_256, k2_256)
    let tweak = hexToBytes("00000000000000000000000000000001")
    let pt = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617")
    let ct = xts.encrypt(tweak, pt)
    let rt = xts.decrypt(tweak, ct)
    doAssert rt == pt
  # Optional: enable XTS official vectors by placing NIST RSP files under ./xts_vectors
  # and setting AES_ENABLE_XTS_VECTORS=1
  block:
    if false: discard # placeholder to keep block
    if os.getEnv("AES_ENABLE_XTS_VECTORS", "") != "":
      let dir = getEnv("AES_XTS_VECTORS_DIR", "xts_vectors")
      if dirExists(dir):
        proc parseHex(s: string): seq[byte] =
          var h = s.strip().replace(" ", "")
          if h.startsWith("0x") or h.startsWith("0X"): h = h[2..^1]
          result = newSeq[byte](h.len div 2)
          for i in 0 ..< result.len:
            result[i] = byte(parseHexInt(h[2*i .. 2*i+1]))
        proc runFile(path: string) =
          let lines = readFile(path).splitLines()
          var key1, key2, keyComb: seq[byte]
          var tweak, pt, ct: seq[byte]
          var have, tests: int
          for ln in lines:
            let line = ln.strip()
            if line.len == 0 or line.startsWith("#") or line.startsWith("[" ) or line.startsWith("COUNT"):
              continue
            if line.contains("Key1 ="):
              key1 = parseHex(line.split("=")[1])
            elif line.contains("Key2 ="):
              key2 = parseHex(line.split("=")[1])
            elif line.startsWith("Key ="):
              keyComb = parseHex(line.split("=")[1])
            elif line.startsWith("i =") or line.startsWith("IV =") or line.startsWith("Tweak ="):
              tweak = parseHex(line.split("=")[1])
            elif line.startsWith("PT ="):
              pt = parseHex(line.split("=")[1])
            elif line.startsWith("CT ="):
              ct = parseHex(line.split("=")[1])
            if tweak.len == 16 and pt.len > 0 and (keyComb.len in {32,64} or (key1.len>0 and key2.len>0)) and ct.len > 0:
              var xts: aesXtsCtx
              if keyComb.len in {32,64}:
                xts = newAesXtsCtx(keyComb)
              else:
                xts = newAesXtsCtx(key1, key2)
              let got = xts.encrypt(tweak, pt)
              doAssert got == ct, "XTS encrypt mismatch in " & path
              let dec = xts.decrypt(tweak, ct)
              doAssert dec == pt, "XTS decrypt mismatch in " & path
              inc tests
              # reset per-test
              tweak.setLen(0); pt.setLen(0); ct.setLen(0); key1.setLen(0); key2.setLen(0); keyComb.setLen(0)
          echo "XTS vectors passed in ", path, ": ", tests
        for path in walkDirRec(dir):
          let p = path
          if p.toLowerAscii().endsWith(".rsp") or p.toLowerAscii().contains("xtsgen"):
            runFile(p)
      else:
        echo "XTS vectors dir not found: ", dir
  # XTS basic round-trips (optional, uncomment to run)
  # block:
  #   let k1 = hexToBytes("27182818284590452353602874713526")
  #   let k2 = hexToBytes("31415926535897932384626433832795")
  #   var xts = newAesXtsCtx(k1, k2)
  #   let tweak = hexToBytes("000102030405060708090a0b0c0d0e0f")
  #   let pt = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021")
  #   let ct = xts.encrypt(tweak, pt)
  #   let rt = xts.decrypt(tweak, ct)
  #   doAssert rt == pt
