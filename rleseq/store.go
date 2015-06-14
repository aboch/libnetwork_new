package rleseq

import (
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/types"
)

func (h *Handle) Key() []string {
	h.Lock()
	defer h.Unlock()
	return []string{h.App, h.ID}
}

func (h *Handle) KeyPrefix() []string {
	h.Lock()
	defer h.Unlock()
	return []string{h.App}
}

func (h *Handle) Value() []byte {
	h.Lock()
	head := h.Head
	h.Unlock()
	if head == nil {
		return []byte{}
	}
	b, err := head.ToByteArray()
	if err != nil {
		return []byte{}
	}
	return b
}

func (h *Handle) Index() uint64 {
	h.Lock()
	defer h.Unlock()
	return h.dbIndex
}

func (h *Handle) SetIndex(index uint64) {
	h.Lock()
	h.dbIndex = index
	h.Unlock()
}

func (h *Handle) watchForChanges() error {
	h.Lock()
	store := h.store
	h.Unlock()

	if store == nil {
		return nil
	}

	kvpChan, err := store.KVStore().Watch(datastore.Key(h.Key()...), nil)
	if err != nil {
		return err
	}
	go func() {
		select {
		case kvPair := <-kvpChan:
			h.Lock()
			if h.dbIndex != kvPair.LastIndex {
				h.dbIndex = kvPair.LastIndex
				h.Head.FromByteArray(kvPair.Value)
			}
			h.Unlock()
		}
	}()
	return nil
}

func (h *Handle) writeToStore() error {
	h.Lock()
	store := h.store
	h.Unlock()
	if store == nil {
		return nil
	}
	err := store.PutObjectAtomic(h)
	if err == datastore.ErrKeyModified {
		return types.RetryErrorf("failed to perform atomic write (%v). retry might fix the error", err)
	}
	return err
}

func (h *Handle) deleteFromStore() error {
	h.Lock()
	store := h.store
	h.Unlock()
	if store == nil {
		return nil
	}
	return store.DeleteObjectAtomic(h)
}
