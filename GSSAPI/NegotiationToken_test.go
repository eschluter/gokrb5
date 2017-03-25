package GSSAPI

import (
	"testing"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
)

const (
	test_negTokenInit = "308202a6a027302506092a864886f71201020206052b0501050206092a864882f71201020206062b0601050205a2820279048202756082027106092a864886f71201020201006e8202603082025ca003020105a10302010ea20703050000000000a38201706182016c30820168a003020105a10d1b0b544553542e474f4b524235a2233021a003020103a11a30181b04485454501b10686f73742e746573742e676f6b726235a382012b30820127a003020112a103020102a282011904820115d4bd890abc456f44e2e7a2e8111bd6767abf03266dfcda97c629af2ece450a5ae1f145e4a4d1bc2c848e66a6c6b31d9740b26b03cdbd2570bfcf126e90adf5f5ebce9e283ff5086da47b129b14fc0aabd4d1df9c1f3c72b80cc614dfc28783450b2c7b7749651f432b47aaa2ff158c0066b757f3fb00dd7b4f63d68276c76373ecdd3f19c66ebc43a81e577f3c263b878356f57e8d6c4eccd587b81538e70392cf7e73fc12a6f7c537a894a7bb5566c83ac4d69757aa320a51d8d690017aebf952add1889adfc3307b0e6cd8c9b57cf8589fbe52800acb6461c25473d49faa1bdceb8bce3f61db23f9cd6a09d5adceb411e1c4546b30b33331e570fd6bc50aa403557e75f488e759750ea038aab6454667d9b64f41a481d23081cfa003020112a281c70481c4eb593beb5afcb1a2a669d54cb85a3772231559f2d40c9f8f053f218ba6eb084ed7efc467d94b88bcd189dda920d6e675ec001a6a2bca11f0a1de37f2f7ae9929f94a86d625b2ec1b213a88cbae6099dda7b172cd3bd1802cb177ae4554d59277004bfd3435248f55044fe7af7b2c9c5a3c43763278c585395aebe2856cdff9f2569d8b823564ce6be2d19748b910ec06bd3c0a9bc5de51ddcf7d875f1108ca6ad935f52d90cb62a18197d9b8e796bef0fbe1463f61df61cfbce6008ae9e1a2d2314a986d"
)

func TestUnmarshal_negTokenInit(t *testing.T) {
	b, err := hex.DecodeString(test_negTokenInit)
	if err != nil{
		t.Fatalf("Error converting hex string test data to bytes: %v", err)
	}
	var n NegotiationToken

	isInit, nt, err := n.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshalling negotiation token: %v", err)
	}
	nInit := nt.(NegTokenInit)
	assert.True(t, isInit, "Boolean indicating type is negTokenInit is not true")
	assert.Equal(t, 4, len(nInit.Body.MechTypes))
}