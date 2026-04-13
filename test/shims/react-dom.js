// Re-export window.ReactDOM as an ES module.
const RD = window.ReactDOM;
export default RD;
export const { createPortal, flushSync, render } = RD;
