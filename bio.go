// Copyright (C) 2014 Space Monkey, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build cgo

package openssl

/*
#include <string.h>
#include <openssl/bio.h>

extern int cbioNew(BIO *b);
static int cbioFree(BIO *b) {
	return 1;
}

extern int writeBioWrite(BIO *b, char *buf, int size);
extern long writeBioCtrl(BIO *b, int cmd, long arg1, void *arg2);
static int writeBioPuts(BIO *b, const char *str) {
    return writeBioWrite(b, (char*)str, (int)strlen(str));
}

extern int readBioRead(BIO *b, char *buf, int size);
extern long readBioCtrl(BIO *b, int cmd, long arg1, void *arg2);

static BIO_METHOD writeBioMethod = {
    BIO_TYPE_SOURCE_SINK,
    "Go Write BIO",
    (int (*)(BIO *, const char *, int))writeBioWrite,
    NULL,
    writeBioPuts,
    NULL,
    writeBioCtrl,
    cbioNew,
    cbioFree,
    NULL};

static BIO_METHOD* BIO_s_writeBio() { return &writeBioMethod; }

static BIO_METHOD readBioMethod = {
    BIO_TYPE_SOURCE_SINK,
    "Go Read BIO",
    NULL,
    readBioRead,
    NULL,
    NULL,
    readBioCtrl,
    cbioNew,
    cbioFree,
    NULL};

static BIO_METHOD* BIO_s_readBio() { return &readBioMethod; }
*/
import "C"

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"sync"
	"unsafe"
)

const (
	SSLRecordSize = 16 * 1024
)

func nonCopyGoBytes(ptr uintptr, length int) []byte {
	var slice []byte
	header := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	header.Cap = length
	header.Len = length
	header.Data = ptr
	return slice
}

func nonCopyCString(data *C.char, size C.int) []byte {
	return nonCopyGoBytes(uintptr(unsafe.Pointer(data)), int(size))
}

//export cbioNew
func cbioNew(b *C.BIO) C.int {
	b.shutdown = 1
	b.init = 1
	b.num = -1
	b.ptr = nil
	b.flags = 0
	return 1
}

type writeBio struct {
	data_mtx        sync.Mutex
	op_mtx          sync.Mutex
	buf             []byte
	release_buffers bool
}

func loadWritePtr(b *C.BIO) *writeBio {
	return (*writeBio)(unsafe.Pointer(b.ptr))
}

func bioClearRetryFlags(b *C.BIO) {
	// from BIO_clear_retry_flags and BIO_clear_flags
	b.flags &= ^(C.BIO_FLAGS_RWS | C.BIO_FLAGS_SHOULD_RETRY)
}

func bioSetRetryRead(b *C.BIO) {
	// from BIO_set_retry_read and BIO_set_flags
	b.flags |= (C.BIO_FLAGS_READ | C.BIO_FLAGS_SHOULD_RETRY)
}

//export writeBioWrite
func writeBioWrite(b *C.BIO, data *C.char, size C.int) (rc C.int) {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: writeBioWrite panic'd: %v", err)
			rc = -1
		}
	}()
	ptr := loadWritePtr(b)
	if ptr == nil || data == nil || size < 0 {
		return -1
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	bioClearRetryFlags(b)
	ptr.buf = append(ptr.buf, nonCopyCString(data, size)...)
	return size
}

//export writeBioCtrl
func writeBioCtrl(b *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) (
	rc C.long) {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: writeBioCtrl panic'd: %v", err)
			rc = -1
		}
	}()
	switch cmd {
	case C.BIO_CTRL_WPENDING:
		return writeBioPending(b)
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		return 1
	default:
		return 0
	}
}

func writeBioPending(b *C.BIO) C.long {
	ptr := loadWritePtr(b)
	if ptr == nil {
		return 0
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	return C.long(len(ptr.buf))
}

func (b *writeBio) WriteTo(w io.Writer) (rv int64, err error) {
	b.op_mtx.Lock()
	defer b.op_mtx.Unlock()

	// write whatever data we currently have
	b.data_mtx.Lock()
	data := b.buf
	b.data_mtx.Unlock()

	if len(data) == 0 {
		return 0, nil
	}
	n, err := w.Write(data)

	// subtract however much data we wrote from the buffer
	b.data_mtx.Lock()
	b.buf = b.buf[:copy(b.buf, b.buf[n:])]
	if b.release_buffers && len(b.buf) == 0 {
		b.buf = nil
	}
	b.data_mtx.Unlock()

	return int64(n), err
}

func (self *writeBio) Disconnect(b *C.BIO) {
	if loadWritePtr(b) == self {
		b.ptr = nil
	}
}

func (b *writeBio) MakeCBIO() *C.BIO {
	rv := C.BIO_new(C.BIO_s_writeBio())
	rv.ptr = unsafe.Pointer(b)
	return rv
}

type readBio struct {
	data_mtx        sync.Mutex
	op_mtx          sync.Mutex
	buf             *bytes.Buffer
	eof             bool
	release_buffers bool
}

func loadReadPtr(b *C.BIO) *readBio {
	return (*readBio)(unsafe.Pointer(b.ptr))
}

// BytesBufferPool is used to recycle bytes.Buffers since they have an internal
// buffer that grows as needed and can be reused.  By reusing buffers, lower
// memory allocations are needed and the garbage collection minimized.
type bytesBufferPool struct {
	pool sync.Pool
}

// NewBytesBufferPool creates a new BytesBufferPool.
func newBytesBufferPool() *bytesBufferPool {
	p := bytesBufferPool{}
	p.pool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
	return &p
}

var bufPool = newBytesBufferPool()

// Get returns a new bytes.Buffer that can be immediately reused. The pool will
// be checked for instances that can be reused, otherwise a new one will be
// created.
func (b *bytesBufferPool) Get() *bytes.Buffer {
	return b.pool.Get().(*bytes.Buffer)
}

// Put puts a bytes.Buffer returned from Get() back into the pool of instances
// that can be reused.  After an item is returned it should never be used.  The
// bytes.Buffer is cleared before putting back into the pool.
func (b *bytesBufferPool) Put(buf *bytes.Buffer) {
	buf.Reset()
	b.pool.Put(buf)
}

//export readBioRead
func readBioRead(b *C.BIO, data *C.char, size C.int) (rc C.int) {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: readBioRead panic'd: %v", err)
			rc = -1
		}
	}()
	ptr := loadReadPtr(b)
	if ptr == nil || size < 0 {
		return -1
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	bioClearRetryFlags(b)
	if ptr.buf.Len() == 0 {
		if ptr.eof {
			return 0
		}
		bioSetRetryRead(b)
		return -1
	}
	if size == 0 || data == nil {
		return C.int(ptr.buf.Len())
	}
	n, _ := ptr.buf.Read(nonCopyCString(data, size))
	return C.int(n)
}

//export readBioCtrl
func readBioCtrl(b *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) (
	rc C.long) {

	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: readBioCtrl panic'd: %v", err)
			rc = -1
		}
	}()
	switch cmd {
	case C.BIO_CTRL_PENDING:
		return readBioPending(b)
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		return 1
	default:
		return 0
	}
}

func readBioPending(b *C.BIO) C.long {
	ptr := loadReadPtr(b)
	if ptr == nil {
		return 0
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	return C.long(ptr.buf.Len())
}

var readBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, SSLRecordSize*2)
		return &b
	},
}

func (b *readBio) ReadFromOnce(r io.Reader) (int, error) {
	b.op_mtx.Lock()
	defer b.op_mtx.Unlock()

	// make sure we have a destination that fits at least one SSL record
	tmpBuf := readBufPool.Get().(*[]byte)
	x, e := r.Read(*tmpBuf)
	if x > 0 {
		b.data_mtx.Lock()
		b.buf.Write((*tmpBuf)[:x])
		b.data_mtx.Unlock()
	}
	readBufPool.Put(tmpBuf)
	return int(x), e
}

func (b *readBio) MakeCBIO() *C.BIO {
	b.buf = bufPool.Get()
	rv := C.BIO_new(C.BIO_s_readBio())
	rv.ptr = unsafe.Pointer(b)
	return rv
}

func (self *readBio) Disconnect(b *C.BIO) {
	if loadReadPtr(b) == self {
		bufPool.Put(self.buf)
		b.ptr = nil
	}
}

func (b *readBio) MarkEOF() {
	b.data_mtx.Lock()
	defer b.data_mtx.Unlock()
	b.eof = true
}

type anyBio C.BIO

func asAnyBio(b *C.BIO) *anyBio { return (*anyBio)(b) }

func (b *anyBio) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n = int(C.BIO_read((*C.BIO)(b), unsafe.Pointer(&buf[0]), C.int(len(buf))))
	if n <= 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (b *anyBio) Write(buf []byte) (written int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := int(C.BIO_write((*C.BIO)(b), unsafe.Pointer(&buf[0]),
		C.int(len(buf))))
	if n != len(buf) {
		return n, errors.New("BIO write failed")
	}
	return n, nil
}

