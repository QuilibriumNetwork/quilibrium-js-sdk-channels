# PasskeyModal Style Test

Visual testing environment for the PasskeyModal component with inline component code for rapid styling iteration.

## Quick Start

From the main project directory:

```bash
npm test
```

Or serve directly with any HTTP server:

```bash
cd test
python3 -m http.server 8080
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
- **Key Icon** - Uses `passkey.png` background image with proper centering
- **Button Colors** - Subtle and elegant:
  - Continue: `slate-600/700` (was bright blue)
  - Proceed Without Passkeys: `amber-600/700` (was yellow)
  - Cancel: `gray-400/500` (was gray-600)
- **Layout** - Properly centered elements with `flex` containers
- **Effects** - Subtle shadows and smooth transitions

### Modal States

1. **Default State** - Pulsating passkey icon with animation
2. **Import Mode** - File dropzone for key import  
3. **Success State** - Green checkmark with success message
4. **Error State** - Red exclamation with error details and options

### Responsive Design
- **Desktop** - 500px wide modal
- **Mobile** - 300px wide modal with responsive scaling

## Development Workflow

⚠️ **Important**: The test file contains an inline copy of the PasskeyModal component for rapid styling iteration. Changes must be manually synced.

1. **Edit styling** directly in `test/index.html` 
2. **Test changes** by refreshing browser
3. **Copy approved changes** to `src/components/modals/PasskeyModal.tsx`
4. **Build** with `npm run build` for production

### Syncing Changes
When updating styles, you need to manually copy the relevant class changes from the test file to the real component. The test file uses an inline component copy to avoid build dependencies and enable instant feedback.

## Files

- `index.html` - Main test page with inline PasskeyModal component  
- `README.md` - This documentation

Uses CDN links for React and Tailwind CSS - no build step required!

---
*Updated: 2025-07-22*