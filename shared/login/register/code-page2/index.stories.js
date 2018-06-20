// @flow
import * as PropProviders from '../../../stories/prop-providers'
import * as React from 'react'
import CodePage2 from '.'
import {action, storiesOf} from '../../../stories/storybook'
import {qrGenerate} from '../../../constants/login'
import * as Helper from './helper'

const textCode = 'scrub disagree sheriff holiday cabin habit mushroom member four'

const props = (currentDeviceAlreadyProvisioned, currentDeviceType, otherDeviceName, otherDeviceType) => {
  const params = {
    currentDeviceAlreadyProvisioned,
    currentDeviceType,
    otherDeviceName,
    otherDeviceType,
  }

  return {
    currentDeviceAlreadyProvisioned,
    currentDeviceType,
    defaultMode: Helper.getDefaultMode(params),
    enterQrCodeInstructions: ``,
    enterTextCodeInputHint: Helper.getEnterTextCodeInputHint(params),
    enterTextCodeInstructions: Helper.getEnterTextCodeInstructions(params),
    isValidLookingCode: value => value.split(' ').length === 12,
    onSubmitTextCode: action('onSubmitTextCode'),
    otherDeviceType,
    validModes: Helper.getValidModes(params),
    viewQrCode: qrGenerate(textCode),
    viewQrCodeInstructions: `View qr code instructions of some length that might explain what the user should be doing`,
    viewTextCode: textCode,
    viewTextCodeInstructions: `View text code instructions`,
  }
}

const load = () => {
  // make it easy to see both sides of the provisioning
  const variants = [
    {current: 'desktop', otherType: 'desktop', provisioned: true},
    {current: 'desktop', otherType: 'desktop', provisioned: false},
    {current: 'phone', otherType: 'phone', provisioned: true},
    {current: 'phone', otherType: 'phone', provisioned: false},
    {current: 'phone', otherType: 'desktop', provisioned: true},
    {current: 'desktop', otherType: 'phone', provisioned: false},
    {current: 'phone', otherType: 'desktop', provisioned: false},
    {current: 'desktop', otherType: 'phone', provisioned: true},
  ]
  variants.forEach(({current, provisioned, otherType}) => {
    let otherName
    switch (otherType) {
      case 'desktop':
        otherName = 'MacbookPro13'
        break
      case 'phone':
        otherName = 'iPhoneX'
        break
      case null:
        otherName = null
        break
    }

    const storyName = `${provisioned ? 'An Existing' : 'A New'} ${current} ${
      provisioned ? ' adding ' : ' added by '
    } ${provisioned ? 'a New' : 'An Existing'} ${otherType}`

    storiesOf(`Register/CodePage2`, module)
      .addDecorator(PropProviders.Common())
      .add(storyName, () => <CodePage2 {...props(provisioned, current, otherName, otherType)} />)
  })
}

export default load
