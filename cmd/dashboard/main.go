package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/roasbeef/bip32-pq-zkp/batchclaim"
	"github.com/roasbeef/bip32-pq-zkp/bip32"
)

// DeriveRequest defines the request body for Taproot derivation.
type DeriveRequest struct {
	SeedHex      string `json:"seed_hex"`
	PathStr      string `json:"path"`
	RequireBIP86 bool   `json:"require_bip86"`
}

// DeriveResponse defines the response with derived cryptographic material.
type DeriveResponse struct {
	TaprootOutputKey string `json:"taproot_output_key"`
	InternalKey      string `json:"internal_key"`
	PathCommitment   string `json:"path_commitment"`
	JournalHex       string `json:"journal_hex"`
	Version          uint32 `json:"version"`
	Flags            uint32 `json:"flags"`
	RequireBIP86     bool   `json:"require_bip86"`
	AddressMainnet   string `json:"address_mainnet"`
	AddressTestnet   string `json:"address_testnet"`
}

// BatchRequest defines the input for batch Merkle tree calculation.
type BatchRequest struct {
	Leaves []string `json:"leaves"` // Hex-encoded leaf journals or seeds
}

// BatchResponse returns the calculated Merkle root and tree details.
type BatchResponse struct {
	LeafCount uint32             `json:"leaf_count"`
	RootHex   string             `json:"root_hex"`
	Leaves    []BatchLeafInfo    `json:"leaves"`
}

// BatchLeafInfo holds info and inclusion proof for one leaf.
type BatchLeafInfo struct {
	Index        uint32   `json:"index"`
	LeafClaimHex string   `json:"leaf_claim_hex"`
	LeafHashHex  string   `json:"leaf_hash_hex"`
	ProofHex     []string `json:"proof_hex"`
}

// SystemStatusResponse provides runtime diagnostic data.
type SystemStatusResponse struct {
	ProjectName       string `json:"project_name"`
	GoVersion         string `json:"go_version"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	MetalAcceleration bool   `json:"metal_acceleration"`
	ImageID           string `json:"image_id"`
}

func parseBIP32Path(pathStr string) ([]uint32, error) {
	trimmed := strings.TrimSpace(pathStr)
	trimmed = strings.TrimPrefix(trimmed, "m/")
	trimmed = strings.TrimPrefix(trimmed, "m")
	if trimmed == "" {
		return nil, nil
	}
	parts := strings.Split(trimmed, "/")
	if len(parts) == 1 && strings.Contains(parts[0], ",") {
		parts = strings.Split(parts[0], ",")
	}

	path := make([]uint32, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		isHardened := strings.HasSuffix(p, "'") || strings.HasSuffix(p, "h") || strings.HasSuffix(p, "H")
		clean := strings.TrimRight(p, "'hH")
		idx, err := strconv.ParseUint(clean, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid path segment %q: %w", p, err)
		}
		val := uint32(idx)
		if isHardened {
			val += bip32.HardenedKeyStart
		}
		path = append(path, val)
	}
	return path, nil
}

// encodeBech32m converts a 32-byte witness program to bech32m Taproot address.
func encodeTaprootAddress(hrp string, outputKey [32]byte) string {
	// Simple BIP-350 bech32m encoder for display
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	const bech32mConst = 0x2bc830a3

	polyMod := func(values []int) int {
		chk := 1
		for _, v := range values {
			top := chk >> 25
			chk = ((chk & 0x1ffffff) << 5) ^ v
			for i := 0; i < 5; i++ {
				if (top>>i)&1 == 1 {
					switch i {
					case 0:
						chk ^= 0x3b6a57b2
					case 1:
						chk ^= 0x26508e6d
					case 2:
						chk ^= 0x1ea119fa
					case 3:
						chk ^= 0x3d4233dd
					case 4:
						chk ^= 0x2a1462b3
					}
				}
			}
		}
		return chk
	}

	hrpExpand := func(s string) []int {
		out := make([]int, 0, len(s)*2+1)
		for i := 0; i < len(s); i++ {
			out = append(out, int(s[i]>>5))
		}
		out = append(out, 0)
		for i := 0; i < len(s); i++ {
			out = append(out, int(s[i]&31))
		}
		return out
	}

	// 8-bit to 5-bit conversion with witness version 1 prepended
	data5 := []int{1} // witness version 1 for Taproot
	acc := 0
	bits := 0
	for _, b := range outputKey {
		acc = (acc << 8) | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			data5 = append(data5, (acc>>bits)&31)
		}
	}
	if bits > 0 {
		data5 = append(data5, (acc<<(5-bits))&31)
	}

	values := append(hrpExpand(hrp), data5...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := polyMod(values) ^ bech32mConst

	checksum := make([]int, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = (mod >> (5 * (5 - i))) & 31
	}

	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteString("1")
	for _, d := range data5 {
		sb.WriteByte(charset[d])
	}
	for _, c := range checksum {
		sb.WriteByte(charset[c])
	}
	return sb.String()
}

func handleDerive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DeriveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Default to BIP-32 test vector 1 if empty
	seedHex := strings.TrimSpace(req.SeedHex)
	if seedHex == "" {
		seedHex = "000102030405060708090a0b0c0d0e0f"
	}

	seedBytes, err := hex.DecodeString(seedHex)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid seed hex: %v", err), http.StatusBadRequest)
		return
	}

	pathStr := strings.TrimSpace(req.PathStr)
	if pathStr == "" {
		pathStr = "m/86'/0'/0'/0/0"
	}

	path, err := parseBIP32Path(pathStr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var opts []bip32.TaprootDeriveOption
	if req.RequireBIP86 {
		opts = append(opts, bip32.WithBIP86PathVerification())
	}

	claim, err := bip32.DeriveTaprootClaim(seedBytes, path, opts...)
	if err != nil {
		http.Error(w, fmt.Sprintf("derive taproot claim: %v", err), http.StatusInternalServerError)
		return
	}

	internalKey, _ := bip32.DeriveXOnly(seedBytes, path)
	journalBytes := claim.Encode()

	resp := DeriveResponse{
		TaprootOutputKey: hex.EncodeToString(claim.TaprootOutputKey[:]),
		InternalKey:      hex.EncodeToString(internalKey),
		PathCommitment:   hex.EncodeToString(claim.PathCommitment[:]),
		JournalHex:       hex.EncodeToString(journalBytes),
		Version:          claim.Version,
		Flags:            claim.Flags,
		RequireBIP86:     claim.Flags&bip32.ClaimFlagRequireBIP86 != 0,
		AddressMainnet:   encodeTaprootAddress("bc", claim.TaprootOutputKey),
		AddressTestnet:   encodeTaprootAddress("tb", claim.TaprootOutputKey),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// If no leaves provided, generate a default sample of 4 leaves
	if len(req.Leaves) == 0 {
		seeds := []string{
			"000102030405060708090a0b0c0d0e0f",
			"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2",
			"4b38042bd98c13f2cd4e8674b4b8c5c9ce2c02c300a8b1712d93d6d53857e077",
			"3333333333333333333333333333333333333333333333333333333333333333",
		}
		req.Leaves = seeds
	}

	leavesBytes := make([][]byte, len(req.Leaves))
	for i, leafStr := range req.Leaves {
		trimmed := strings.TrimSpace(leafStr)
		bytes, err := hex.DecodeString(trimmed)
		if err != nil || len(bytes) != 72 {
			// If not a 72-byte journal, treat as seed and derive full Taproot claim
			seedBytes, _ := hex.DecodeString(trimmed)
			if len(seedBytes) == 0 {
				seedBytes = []byte(trimmed)
			}
			path := []uint32{bip32.BIP86Purpose, bip32.HardenedKeyStart, bip32.HardenedKeyStart, 0, uint32(i)}
			claim, _ := bip32.DeriveTaprootClaim(seedBytes, path, bip32.WithBIP86PathVerification())
			bytes = claim.Encode()
		}
		leavesBytes[i] = bytes
	}

	root, err := batchclaim.Root(leavesBytes, sha256.Sum256)
	if err != nil {
		http.Error(w, fmt.Sprintf("construct merkle tree: %v", err), http.StatusBadRequest)
		return
	}

	leafInfos := make([]BatchLeafInfo, len(leavesBytes))
	for i := range leavesBytes {
		proof, _, err := batchclaim.BuildProof(leavesBytes, i, sha256.Sum256)
		if err != nil {
			continue
		}
		leafHash := batchclaim.LeafHash(uint32(i), leavesBytes[i], sha256.Sum256)
		siblingHex := make([]string, len(proof.Siblings))
		for sIdx, sib := range proof.Siblings {
			siblingHex[sIdx] = hex.EncodeToString(sib[:])
		}
		leafInfos[i] = BatchLeafInfo{
			Index:        uint32(i),
			LeafClaimHex: hex.EncodeToString(leavesBytes[i]),
			LeafHashHex:  hex.EncodeToString(leafHash[:]),
			ProofHex:     siblingHex,
		}
	}

	resp := BatchResponse{
		LeafCount: uint32(len(leavesBytes)),
		RootHex:   hex.EncodeToString(root[:]),
		Leaves:    leafInfos,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	metalAcc := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && os.Getenv("RISC0_FORCE_CPU_PROVER") == ""

	resp := SystemStatusResponse{
		ProjectName:       "VeriTx",
		GoVersion:         runtime.Version(),
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		MetalAcceleration: metalAcc,
		ImageID:           "8a6a2c27dd54d8fa0f99a332b57cb105f88472d977c84bfac077cbe70907a690",
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func main() {
	port := flag.Int("port", 8080, "HTTP server port")
	flag.Parse()

	// Find static assets directory relative to executable or current workdir
	execPath, err := os.Executable()
	var staticDir string
	if err == nil {
		candidate := filepath.Join(filepath.Dir(execPath), "static")
		if _, err := os.Stat(candidate); err == nil {
			staticDir = candidate
		}
	}
	if staticDir == "" {
		candidate := filepath.Join("cmd", "dashboard", "static")
		if _, err := os.Stat(candidate); err == nil {
			staticDir = candidate
		} else {
			staticDir = "static"
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/derive", handleDerive)
	mux.HandleFunc("/api/batch", handleBatch)
	mux.HandleFunc("/api/status", handleStatus)

	fileServer := http.FileServer(http.Dir(staticDir))
	mux.Handle("/", fileServer)

	addr := fmt.Sprintf(":%d", *port)
	fmt.Printf("\n✨ VeriTx Post-Quantum ZK Dashboard running at http://localhost:%d\n", *port)
	fmt.Printf("Serving static assets from: %s\n\n", staticDir)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
