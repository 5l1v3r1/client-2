import * as React from 'react'
import * as Sb from '../../stories/storybook'
import * as Types from '../../constants/types/teams'
import EditAvatar from '.'

const provider = Sb.createPropProviderWithCommon()

const props = {
  error: '',
  onBack: Sb.action('onBack'),
  onClose: Sb.action('onClose'),
  onSave: Sb.action('onSave'),
  onSkip: Sb.action('onSkip'),
  submitting: false,
  teamID: Types.noTeamID,
  type: 'profile' as const,
  waitingKey: 'dummyWaitingKey',
  wizard: false,
}

const load = () => {
  Sb.storiesOf('Profile/EditAvatar', module)
    .addDecorator(provider)
    .add('Has', () => <EditAvatar {...props} />)
    .add('Error', () => <EditAvatar {...props} error="Bad avatar. Try another one." />)
}

export default load
