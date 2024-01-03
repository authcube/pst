export function joinAll(a: ArrayBuffer[]): ArrayBuffer {
    let size = 0;
    for (const ai of a) {
        size += ai.byteLength;
    }

    const buffer = new ArrayBuffer(size);
    const view = new Uint8Array(buffer);
    let offset = 0;
    for (const ai of a) {
        view.set(new Uint8Array(ai), offset);
        offset += ai.byteLength;
    }

    return buffer;
}
