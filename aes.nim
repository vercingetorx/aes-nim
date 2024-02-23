import std/[sequtils, strutils]
include rijndael
#[
  key sizes (int bytes -> bits):
    16 -> 128bit
    24 -> 192bit
    32 -> 256bit
]#

const blocksize = 16

type
  aesEcbCtx* = object # Electronic CodeBook
    key:            seq[byte]
    state:          BlockState
  aesCbcCtx* = object # Ciphertext Block Chaining
    key:            seq[byte]
    iv:             seq[byte]
    state:          BlockState
    previousBlock:  array[blocksize, byte]
    isEncryptState: bool
  aesCtrCtx* = object # Counter
    key:            seq[byte]
    nonce:          seq[byte]
    state:          BlockState
    initState:      array[8, byte]
    counter:        array[blocksize, byte]
    isEncryptState: bool


#################################################################################

proc encodeBytes(s: string): seq[byte] =
  ## encode ascii string to bytes
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)
  
  return result


proc decodeBytes(bs: openArray[byte]): string =
  ## decode bytes to ascii string
  result = newStringOfCap(bs.len)
  for i, b in bs:
    result.add(char(b))
  
  return result


proc padPKCS7*(data: openArray[byte]): seq[byte] =
  let paddingLen = 16 - (len(data) mod 16)
  let paddingByte = paddingLen.byte
  result = newSeqOfCap[byte](len(data) + paddingLen)
  result.add(data)
  for _ in 1 .. paddingLen:
    result.add(paddingByte)


proc unpadPKCS7*(data: openArray[byte]): seq[byte] =
  if data.len == 0 or data.len mod 16 != 0:
    raise newException(ValueError, "Invalid padded data length")
  
  let paddingLen = data[^1].int
  if paddingLen < 1 or paddingLen > 16:
    raise newException(ValueError, "Invalid padding length")
  
  for i in 1 .. paddingLen:
    if data[data.len - i] != paddingLen.byte:
      raise newException(ValueError, "Invalid padding")
  result = data[0 ..< data.len - paddingLen]


proc xorBlocks(this: var openArray[byte], that: openArray[byte]) =
  for i in 0 ..< this.len:
    this[i] = this[i] xor that[i]


proc xorBlocks(this: openArray[byte], that: openArray[byte]): array[blocksize, byte] =
  for i in 0 ..< this.len:
    result[i] = this[i] xor that[i]


proc xorBlocksSeq(this: openArray[byte], that: openArray[byte]): seq[byte] =
  result = newSeq[byte](this.len)
  for i in 0 ..< this.len:
    result[i] = this[i] xor that[i]


proc initPreviousBlock(ctx: var aesCbcCtx) =
  ## initialize previous block with IV
  for i, b in ctx.iv:
    ctx.previousBlock[i] = b


proc initCounter*(ctx: var aesCtrCtx) =
  ## initialize counter with IV
  for i, b in ctx.nonce:
    ctx.counter[i] = b
  for i, b in ctx.initState:
    ctx.counter[8 + i] = b


proc incrementCounter(ctx: var aesCtrCtx) =
  for i in countdown(15, 8):
    ctx.counter[i] = ctx.counter[i] + 1
    if ctx.counter[i] != 0:  # No overflow for this byte
      return
  raise newException(OverflowDefect, "counter overflow")


proc intToBytesBE(n: uint64): seq[byte] =
  ## big endian
  result = newSeq[byte](8)
  for i in 0 ..< 8:
    result[7 - i] = byte((n shr (i * 8)) and 0xFF)


proc intToBytesBE(n: int): seq[byte] =
  ## big endian
  result = newSeq[byte](4)
  for i in 0 ..< 4:
    result[3 - i] = byte((n shr (i * 4)) and 0xFF)


proc hexDigest*(data: openArray[byte]): string =
  ## produces a hex string of length data.len * 2
  result = newStringOfCap(data.len + data.len)
  for b in data:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc `$`*(data: seq[byte]): string =
  return decodeBytes(data)

#################################################################################
# ECB
#################################################################################

proc encrypt*(ctx: aesEcbCtx, input: openArray[byte], output: var openArray[byte]) =
  ## ECB Mode
  ## encrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  for i in countup(0, input.len - 1, step=blocksize):
    rijndaelEncrypt(ctx.state.ek, ctx.state.rounds, input[i ..< i + blocksize], blk)
    for j, b in blk:
      output[i + j] = b


proc encrypt*(ctx: aesEcbCtx, input: openArray[byte]): seq[byte] =
  ## ECB Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  for i in countup(0, input.len - 1, step=blocksize):
    rijndaelEncrypt(ctx.state.ek, ctx.state.rounds, input[i ..< i + blocksize], blk)
    for j, b in blk:
      result[i + j] = b

  return result


proc encrypt*(ctx: aesEcbCtx, input: string, output: var openArray[byte]) =
  ## ECB Mode
  ## encrypt in place
  encrypt(ctx, input.encodeBytes(), output)


proc encrypt*(ctx: aesEcbCtx, input: string): seq[byte] =
  ## ECB Mode
  ## returns ciphertext as new sequence
  return encrypt(ctx, input.toOpenArrayByte(0, input.len.pred))


proc decrypt*(ctx: aesEcbCtx, input: openArray[byte], output: var openArray[byte]) =
  ## EBC Mode
  ## decrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  for i in countup(0, input.len.pred, step=blocksize):
    rijndaelDecrypt(ctx.state.dk, ctx.state.rounds, input, blk)
    for j, b in blk:
      output[i + j] = b


proc decrypt*(ctx: aesEcbCtx, input: openArray[byte]): seq[byte] =
  ## EBC Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  for i in countup(0, input.len.pred, step=blocksize):
    rijndaelDecrypt(ctx.state.dk, ctx.state.rounds, input[i ..< i + blocksize], blk)
    for j, b in blk:
      result[i + j] = b

  return result


proc decrypt*(ctx: aesEcbCtx, input: string, output: var openArray[byte]) =
  ## EBC Mode
  ## decrypt in place
  decrypt(ctx, input.encodeBytes(), output)


proc decrypt*(ctx: aesEcbCtx, input: string): seq[byte] =
  ## EBC Mode
  ## returns ciphertext as new sequence
  return decrypt(ctx, input.encodeBytes())

#################################################################################
# CBC
#################################################################################

proc encrypt*(ctx: var aesCbcCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CBC Mode
  ## encrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  if not ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = true


  for i in countup(0, input.high, step=blocksize):
    # XOR with previous ciphertext block (or IV)
    rijndaelEncrypt(ctx.state.ek, ctx.state.rounds, xorBlocks(input[i ..< i + blocksize], ctx.previousBlock), blk)
    for j, b in blk:
      output[i + j] = b
    ctx.previousBlock = blk


proc encrypt*(ctx: var aesCbcCtx, input: openArray[byte]): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  if not ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = true

  for i in countup(0, input.high, step=blocksize):
    # XOR with previous ciphertext block (or IV)
    rijndaelEncrypt(ctx.state.ek, ctx.state.rounds, xorBlocks(input[i ..< i + blocksize], ctx.previousBlock), blk)
    for j, b in blk:
      result[i + j] = b
    ctx.previousBlock = blk

  return result


proc encrypt*(ctx: var aesCbcCtx, input: string, output: var openArray[byte]) =
  ## CBC Mode
  ## encrypt in place
  encrypt(ctx, input.encodeBytes(), output)


proc encrypt*(ctx: var aesCbcCtx, input: string): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  return encrypt(ctx, input.encodeBytes())


proc decrypt*(ctx: var aesCbcCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CBC Mode
  ## decrypt in place
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var ptBlk: array[blocksize, byte]
  var ctBlk: array[blocksize, byte]

  if ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = false

  for i in countup(0, input.high, step=blocksize):
    for i, b in input[i ..< i + blocksize]:
      ptBlk[i] = b
    rijndaelDecrypt(ctx.state.dk, ctx.state.rounds, ptBlk, ctBlk)
    # XOR with previous ciphertext block (or IV for the first block)
    xorBlocks(ctBlk, ctx.previousBlock)
    for j, b in ctBlk:
      output[i + j] = b
    
    ctx.previousBlock = ptBlk


proc decrypt*(ctx: var aesCbcCtx, input: openArray[byte]): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  if input.len mod blocksize != 0:
    raise newException(ValueError, "input length must be a multiple of 16")

  var ptBlk: array[blocksize, byte]
  var ctBlk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  if ctx.isEncryptState:
    ctx.initPreviousBlock()
    ctx.isEncryptState = false

  for i in countup(0, input.high, step=blocksize):
    for i, b in input[i ..< i + blocksize]:
      ptBlk[i] = b
    rijndaelDecrypt(ctx.state.dk, ctx.state.rounds, ptBlk, ctBlk)
    # XOR with previous ciphertext block (or IV for the first block)
    xorBlocks(ctBlk, ctx.previousBlock)
    for j, b in ctBlk:
      result[i + j] = b
    ctx.previousBlock = ptBlk

  return result


proc decrypt*(ctx: var aesCbcCtx, input: string, output: var openArray[byte]) =
  ## CBC Mode
  ## decrypt in place
  decrypt(ctx, input.encodeBytes(), output)


proc decrypt*(ctx: var aesCbcCtx, input: string): seq[byte] =
  ## CBC Mode
  ## returns ciphertext as new sequence
  return decrypt(ctx, input.encodeBytes())

#################################################################################
# CTR
#################################################################################

proc crypt*(ctx: var aesCtrCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CTR Mode
  ## crypt in place
  if input.len > output.len:
    raise newException(ValueError, "output length must be >= input length")

  var blk: array[blocksize, byte]

  for i in countup(0, input.high, step=blocksize):
    # Encrypt the counter
    rijndaelEncrypt(ctx.state.ek, ctx.state.rounds, ctx.counter, blk)
    ctx.incrementCounter()
    # XOR the encrypted counter with the block
    for j, b in xorBlocksSeq(input[i ..< min(i + blocksize, input.len)], blk):
      output[i + j] = b


proc crypt*(ctx: var aesCtrCtx, input: openArray[byte]): seq[byte] =
  ## CTR Mode
  ## returns result as new sequence
  var blk: array[blocksize, byte]
  result = newSeq[byte](input.len)

  for i in countup(0, input.high, step=blocksize):
    # Encrypt the counter
    rijndaelEncrypt(ctx.state.ek, ctx.state.rounds, ctx.counter, blk)
    ctx.incrementCounter()
    # XOR the encrypted counter with the block
    for j, b in xorBlocksSeq(input[i ..< min(i + blocksize, input.len)], blk):
      result[i + j] = b

  return result


proc encrypt*(ctx: var aesCtrCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CTR Mode
  ## encrypt in place
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  crypt(ctx, input, output)


proc encrypt*(ctx: var aesCtrCtx, input: openArray[byte]): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  return crypt(ctx, input)


proc encrypt*(ctx: var aesCtrCtx, input: string, output: var openArray[byte]) =
  ## CTR Mode
  ## encrypt in place
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  crypt(ctx, input.encodeBytes(), output)


proc encrypt*(ctx: var aesCtrCtx, input: string): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if not ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = true
  return crypt(ctx, input.encodeBytes())


proc decrypt*(ctx: var aesCtrCtx, input: openArray[byte], output: var openArray[byte]) =
  ## CTR Mode
  ## decrypt in place
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  crypt(ctx, input, output)


proc decrypt*(ctx: var aesCtrCtx, input: openArray[byte]): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  return crypt(ctx, input)


proc decrypt*(ctx: var aesCtrCtx, input: string, output: var openArray[byte]) =
  ## CTR Mode
  ## decrypt in place
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  crypt(ctx, input.encodeBytes(), output)


proc decrypt*(ctx: var aesCtrCtx, input: string): seq[byte] =
  ## CTR Mode
  ## returns ciphertext as new sequence
  if ctx.isEncryptState:
    ctx.initCounter()
    ctx.isEncryptState = false
  return crypt(ctx, input.encodeBytes())

#################################################################################

proc newAesEcbCtx*(key: openArray[byte]): aesEcbCtx =
  if not key.len in {16, 24, 32}:
    raise newException(ValueError, "Key must be 16/24/32 bytes long")
  result.key = toSeq(key)

  discard stateInit(result.state, result.key, result.key.len)


proc newAesEcbCtx*(key: string): aesEcbCtx =
  return newAesEcbCtx(key.encodeBytes())


proc newAesCbcCtx*(key, iv: openArray[byte]): aesCbcCtx =
  if not key.len in {16, 24, 32}:
    raise newException(ValueError, "Key must be 16/24/32 bytes long")
  if iv.len != 16:
    raise newException(ValueError, "Initialization vector (IV) must be 16 bytes long")
  result.key = toSeq(key)
  result.iv = toSeq(iv)
  result.initPreviousBlock()

  discard stateInit(result.state, result.key, result.key.len)


proc newAesCbcCtx*(key, iv: string): aesCbcCtx =
  return newAesCbcCtx(key.encodeBytes(), iv.encodeBytes())


proc newAesCtrCtx*(key, nonce: openArray[byte], initState: openArray[byte]=newSeq[byte](8)): aesCtrctx =
  if not key.len in {16, 24, 32}:
    raise newException(ValueError, "Key must be 16/24/32 bytes long")
  if nonce.len != 8:
    raise newException(ValueError, "Nonce must be 8 bytes long")
  if initState.len != 8:
    raise newException(ValueError, "Initial state must be 8 bytes long")
  
  result.key = toSeq(key)
  result.nonce = toSeq(nonce)
  for i, b in initState:
    result.initState[i] = b
  result.initCounter()

  discard stateInit(result.state, result.key, result.key.len)


proc newAesCtrCtx*(key, nonce: string, initState: int = 0): aesCtrctx =
  return newAesCtrCtx(key.encodeBytes(), nonce.encodeBytes(), intToBytesBE(uint64(initState)))

#################################################################################

when isMainModule:
  import base64
  
  let
    message = "This is a message of length 32!!" # 32
    key = "0123456789ABCDEFGHIJKLMNOPQRSTUV" # 32
    iv = "0000000000000000" # 16

  var ctx = newAesCbcCtx(key, iv)
  
  let ciphertext = ctx.encrypt(message)
  echo encode(ciphertext)
  doAssert encode(ciphertext) == "ZSKT6i6OJSxAvdnEGAO2hDRnseWzj7pgQGZA0wExlBA="
  
  let plaintext = ctx.decrypt(ciphertext)
  echo plaintext
  doAssert $plaintext == message
