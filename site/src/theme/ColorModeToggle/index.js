import React from 'react';
import { useColorMode } from '@docusaurus/theme-common';
import IconDarkMode from '@theme/Icon/DarkMode';
import IconLightMode from '@theme/Icon/LightMode';
import useIsBrowser from '@docusaurus/useIsBrowser';

export default function ColorModeToggle({ className, buttonClassName }) {
  const { colorMode, setColorMode } = useColorMode();
  const isBrowser = useIsBrowser();

  return (
    <div className={className} style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
      <button
        className={'clean-btn toggleButton ' + (buttonClassName || '') + (!isBrowser ? ' disabled' : '')}
        type="button"
        onClick={() => setColorMode(colorMode === 'dark' ? 'light' : 'dark')}
        disabled={!isBrowser}
        style={{ padding: '4px', background: 'transparent', border: 'none', cursor: isBrowser ? 'pointer' : 'default', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      >
        {isBrowser && (colorMode === 'dark' ? <IconDarkMode /> : <IconLightMode />)}
      </button>
    </div>
  );
}
