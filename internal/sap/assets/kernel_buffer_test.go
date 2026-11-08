package assets

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"testing"
)

type countedZIPReader struct {
	*bytes.Reader
	reads int
}

func (reader *countedZIPReader) ReadAt(data []byte, offset int64) (int, error) {
	reader.reads++
	return reader.Reader.ReadAt(data, offset)
}

func TestRemoteKernelDeflateBatchesRangeReads(t *testing.T) {
	data := make([]byte, 5<<19)
	random := rand.New(rand.NewPCG(1, 2))
	for index := range data {
		data[index] = byte(random.Uint64())
	}
	var encoded bytes.Buffer
	writer := zip.NewWriter(&encoded)
	member, err := writer.Create("kernelcache")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	source := &countedZIPReader{Reader: bytes.NewReader(encoded.Bytes())}
	archive, err := zip.NewReader(source, int64(encoded.Len()))
	if err != nil {
		t.Fatal(err)
	}
	bufferRemoteDeflate(archive)
	reader, err := archive.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	source.reads = 0
	decoded, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(decoded, data) {
		t.Fatal("buffering changed the decoded ZIP member")
	}
	if source.reads > 5 {
		t.Fatalf("compressed payload required %d range reads, expected bounded large reads", source.reads)
	}
	archive.File[0].CRC32 ^= 1
	reader, err = archive.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	_, readErr = io.Copy(io.Discard, reader)
	_ = reader.Close()
	if !errors.Is(readErr, zip.ErrChecksum) {
		t.Fatal("buffered decompression did not retain ZIP checksum validation")
	}
}
