// Type declarations for ?raw imports (used by esbuild raw plugin)
declare module '*.wgsl?raw' {
  const content: string;
  export default content;
}

declare module '*?raw' {
  const content: string;
  export default content;
}
