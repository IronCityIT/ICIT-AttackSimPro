/**
 * Minimal in-memory Firestore double.
 *
 * Test-and-local only — never required by index.js, so it is not part of the
 * deployed runtime. Implements exactly the surface handler.js uses:
 *   db.collection(id).doc(id).collection(id).doc(id) -> { get(), set(data, {merge}) }
 *   snapshot.exists, snapshot.get(field)
 *   db.serverTimestamp()
 */

"use strict";

function makeSnapshot(data) {
  return {
    exists: data !== undefined,
    data: () => (data === undefined ? undefined : { ...data }),
    get: (field) => (data === undefined ? undefined : data[field]),
  };
}

class DocRef {
  constructor(store, path) {
    this.store = store;
    this.path = path;
  }
  collection(id) {
    return new CollectionRef(this.store, this.path + "/" + id);
  }
  async get() {
    return makeSnapshot(this.store.get(this.path));
  }
  async set(data, options = {}) {
    if (options.merge && this.store.has(this.path)) {
      this.store.set(this.path, { ...this.store.get(this.path), ...data });
    } else {
      this.store.set(this.path, { ...data });
    }
  }
}

class CollectionRef {
  constructor(store, path) {
    this.store = store;
    this.path = path;
  }
  doc(id) {
    return new DocRef(this.store, this.path + "/" + id);
  }
}

function createInMemoryFirestore() {
  const store = new Map();
  return {
    collection: (id) => new CollectionRef(store, id),
    serverTimestamp: () => new Date().toISOString(),
    // Test helpers (not part of the Firestore surface):
    _dump: () => Object.fromEntries(store),
    _get: (path) => store.get(path),
  };
}

module.exports = { createInMemoryFirestore };
