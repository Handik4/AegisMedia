// JSON.stringify throws on bigint. Several write arguments (entity ids, timestamps,
// atto-scale values) are bigints, so teach BigInt to serialise as its decimal string.
if (typeof BigInt !== "undefined") {
  const proto = BigInt.prototype as unknown as { toJSON?: () => string };
  if (typeof proto.toJSON !== "function") {
    proto.toJSON = function (this: bigint): string {
      return this.toString();
    };
  }
}
export {};
