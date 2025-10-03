// @unocss-include
import transformerDirectives from '@unocss/transformer-directives'
import { defineConfig, presetWind3 } from 'unocss'
import presetIcons from 'unocss/preset-icons'

const iconSource = 'https://fa.ekopedia.id/icons/svgs'

export default defineConfig({
  presets: [
    presetWind3(),presetIcons({
      cdn: 'https://esm.sh/',
      collections: {
        fab: async (iconName: string) =>
          await fetch(`${iconSource}/brands/${iconName}.svg`).then((res) => res.text()),
        far: async (iconName: string) =>
          await fetch(`${iconSource}/regular/${iconName}.svg`).then((res) => res.text()),
        fas: async (iconName: string) =>
          await fetch(`${iconSource}/solid/${iconName}.svg`).then((res) => res.text()),
      },
      customizations: {
        transform(svg, collection) {
          const fontAwesomeCollection = ['fab', 'far', 'fas']
          if (fontAwesomeCollection.includes(collection)) {
            return svg.replace('<path', '<path fill="currentColor"')
          }
          return svg
        },
      },
    }),
  ],
  transformers: [
    transformerDirectives(), // enable @apply for css
  ],
  theme: {
    container: {
      center: true,
      padding: {
        DEFAULT: '1rem',
      },
    },
    breakpoints: {
      sm: '640px',
      md: '768px',
      lg: '980px',
      xl: '1280px',
      '2xl': '1920px',
    },
    colors: {
      primary: {
        DEFAULT: '#001064',
        50: '#f1f6ff',
        100: '#e5ecff',
        200: '#ceddff',
        300: '#a7bfff',
        400: '#7695ff',
        500: '#3f60ff',
        600: '#1833ff',
        700: '#0725fa',
        800: '#051ed2',
        900: '#061aac',
        950: '#001064',
      },
      gray: {
        DEFAULT: '#999999',
        '50': '#F7F7F7',
        '100': '#EDEDED',
        '200': '#DFDFDF',
        '300': '#C8C8C8',
        '400': '#ACACAC',
        '500': '#999999',
        '600': '#888888',
        '700': '#7B7B7B',
        '800': '#676767',
        '900': '#545454',
        '950': '#363636',
      },
      blue: {
        DEFAULT: '#001064',
        50: '#f1f6ff',
        100: '#e5ecff',
        200: '#ceddff',
        300: '#a7bfff',
        400: '#7695ff',
        500: '#3f60ff',
        600: '#1833ff',
        700: '#0725fa',
        800: '#051ed2',
        900: '#061aac',
        950: '#001064',
      },
      yellow: {
        DEFAULT: '#ffd700',
        '50': '#ffffe7',
        '100': '#feffc1',
        '200': '#fffd86',
        '300': '#fff441',
        '400': '#ffe60d',
        '500': '#ffd700',
        '600': '#d19e00',
        '700': '#a67102',
        '800': '#89580a',
        '900': '#74480f',
        '950': '#442604',
      },
    },
  },
  rules: [
    ['un-cloak', { display: 'block' }],
    ['text-2xs', { 'font-size': '.6875rem' }], // 11px
    ['text-3xs', { 'font-size': '.625rem' }], // 10px
    ['text-4xs', { 'font-size': '.5625rem' }], // 9px
    ['text-5xs', { 'font-size': '.5rem' }], // 8px
    ['word-break-words', {'word-break': 'break-word'}]
  ],
  shortcuts: [
    {
    },
  ],
})
