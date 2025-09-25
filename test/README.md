# PasskeyModal Testing

Testing environment for the PasskeyModal component with both development and production build testing capabilities.

## Quick Start

### Development Testing
For testing styling changes during development:

```bash
yarn test
```

### Production Build Testing
For testing the actual built CSS and ensuring build integrity:

```bash
yarn test-build
```

This command will:
1. Run `yarn build` to compile the project
2. Generate `test-build.html` using the actual built CSS from `dist/index.css`
3. Start a server on `http://localhost:3001`

### Manual Server Setup
Or serve directly with any HTTP server:

```bash
cd test
python3 -m http.server 3001
# or
npx http-server . -p 3001
```

## Test Features

### Control Panel
Use the control panel (top-left) to test different modal states:

- **Show Create Modal** - Default passkey creation flow
- **Show Import Modal** - Key import flow with file dropzone  
- **Show Success State** - Successful registration state
- **Show Error State** - Error state with sample error message
- **Hide Modal** - Close the modal

### Current Styling
- **Modern Responsive Design** - Clean, professional modal with backdrop blur
- **Key Icon** - Uses `passkey.png` background image with proper centering and pulsating animation
- **Button Colors** - Professional color scheme:
  - Continue: Blue (`#0287F2`)
  - Proceed Without Passkeys: Amber (`#d97706`)
  - Cancel: Gray (`#9ca3af`)
- **Layout** - CSS-only styling with proper overflow handling
- **No Horizontal Scrolling** - Fixed container width with `overflow-x: hidden` and `box-sizing: border-box`

### Modal States

1. **Default State** - Pulsating passkey icon with animation
2. **Import Mode** - File dropzone for key import  
3. **Success State** - Green checkmark with success message
4. **Error State** - Red exclamation with error details and options

### Responsive Design
- **Desktop** - 500px wide modal
- **Mobile** - 300px wide modal with responsive scaling

## Development Workflow

### For Style Development
1. **Edit styling** in `src/components/modals/PasskeyModal.css`
2. **Test changes** using `yarn test` (serves from source CSS files)
3. **Verify build** using `yarn test-build` (tests actual compiled CSS)

### Two Testing Modes

#### Development Mode (`yarn test`)
- Uses source CSS files directly (`PasskeyModal.css`)
- Faster iteration for styling changes
- No build step required

#### Production Mode (`yarn test-build`)
- Runs full build process first
- Uses compiled CSS from `dist/index.css`
- Verifies that build process works correctly
- Tests actual CSS that will be shipped

### Recent Fixes
- ✅ **Horizontal Scrolling Fixed** - Added `overflow-x: hidden` and `box-sizing: border-box`
- ✅ **Dropzone Overflow Fixed** - Proper width containment for file upload area
- ✅ **Build Process** - CSS compilation works correctly with PostCSS plugin

## Files

- `index.html` - Development test page with inline PasskeyModal component for rapid iteration
- `test-build.html` - Generated production test page (created by `yarn test-build`)
- `create-build-test.js` - Script that builds project and generates production test
- `PasskeyModal.css` - Copy of source CSS for development testing
- `README.md` - This documentation

## Architecture

- **Source CSS**: `src/components/modals/PasskeyModal.css`
- **Built CSS**: `dist/index.css` (compiled with PostCSS)
- **Test CSS**: `test/PasskeyModal.css` (copy for development)

Uses CDN links for React - no complex build dependencies for testing!

---
*Updated: 2025-07-22*