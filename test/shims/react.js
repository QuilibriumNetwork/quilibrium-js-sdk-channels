// Re-export window.React (loaded via UMD script tag) as an ES module
// so the SDK's `import React from 'react'` resolves to the same instance.
const R = window.React;
export default R;
export const {
  createContext, createElement, forwardRef, Fragment,
  memo, useCallback, useContext, useEffect, useImperativeHandle,
  useMemo, useReducer, useRef, useState,
} = R;
