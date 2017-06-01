// @flow
import {isAndroid} from '../constants/platform'

const colors = {
  beige: '#f7f1eb',
  black: '#000000',
  black_05: 'rgba(0, 0, 0, 0.05)',
  black_10: 'rgba(0, 0, 0, 0.10)',
  black_20: 'rgba(0, 0, 0, 0.20)',
  black_40: 'rgba(0, 0, 0, 0.40)',
  black_60: 'rgba(0, 0, 0, 0.60)',
  black_75: isAndroid ? '#000000' : 'rgba(0, 0, 0, 0.75)',
  blue2: '#66b8ff',
  blue3: '#a8d7ff',
  blue3_60: 'rgba(168, 215, 255, 0.6)',
  blue3_40: 'rgba(168, 215, 255, 0.4)',
  blue4: '#ebf5fc',
  blue5_60: 'rgba(50, 159, 254, 0.6)',
  blue: '#33a0ff',
  blue_30: 'rgba(51, 160, 255, 0.3)',
  brown_60: 'rgba(71, 31, 17, 0.6)',
  darkBlue2: '#2470b3',
  darkBlue3: '#0a3052',
  darkBlue4: '#103c64',
  darkBlue: '#195080',
  green2: '#36b37c',
  green3: '#e5f6ef',
  green: '#3dcc8e',
  grey: '#cccccc',
  lightGrey2: '#e6e6e6',
  lightGrey: '#f0f0f0',
  midnightBlue: '#082640',
  midnightBlue_75: 'rgba(8, 38, 64, 0.75)',
  orange: '#ff6f21',
  red: '#ff4d61',
  red_75: 'rgba(255,0,0,0.75)',
  transparent: 'rgba(0, 0, 0, 0)',
  white: '#ffffff',
  white_0: 'rgba(255, 255, 255, 0)',
  white_40: 'rgba(255, 255, 255, 0.40)',
  white_75: 'rgba(255, 255, 255, 0.75)',
  white_90: 'rgba(255, 255, 255, 0.90)',
  yellow: '#fff75a',
  yellowGreen2: '#94b52f',
  yellowGreen2_75: 'rgba(154, 180, 57, 0.75)',
  yellowGreen3: '#d2e697',
  yellowGreen: '#a8cf36',
}

export default colors
