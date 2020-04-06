import * as React from 'react'
import * as Kb from '../../../common-adapters'
import * as Styles from '../../../styles'
import * as RPCTypes from '../../../constants/types/rpc-gen'
import * as Constants from '../../../constants/teams'
import * as Types from '../../../constants/types/teams'
import * as Container from '../../../util/container'
import * as Chat2Gen from '../../../actions/chat2-gen'
import * as ProfileGen from '../../../actions/profile-gen'
import {useAllChannelMetas} from '../../common/channel-hooks'
import logger from '../../../logger'
import {pluralize} from '../../../util/string'
import {FloatingRolePicker} from '../../role-picker'
import RoleButton from '../../role-button'
import * as TeamsGen from '../../../actions/teams-gen'
import {TeamDetailsSubscriber} from '../../subscriber'
import {formatTimeForTeamMember, formatTimeRelativeToNow} from '../../../util/timestamp'
import {Section as _Section} from '../../../common-adapters/section-list'

type Props = {
  teamID: Types.TeamID
  username: string
}
type OwnProps = Container.RouteProps<Props>

type TeamTreeRowNotIn = {
  teamID: Types.TeamID
  teamname: string
  memberCount?: number
  joinTime?: number
  canAdminister: boolean
}
type TeamTreeRowIn = {
  key: string
  lastActivity: number
  role: Types.TeamRoleType
} & TeamTreeRowNotIn

const getSubteamsInNotIn = (state: Container.TypedState, teamID: Types.TeamID, username: string) => {
  const errors: Array<RPCTypes.TeamTreeMembership> = []
  const subteamsNotIn: Array<TeamTreeRowNotIn> = []
  const subteamsIn: Array<TeamTreeRowIn> = []

  const memberships = state.teams.teamMemberToTreeMemberships.get(teamID)?.get(username)
  if (!memberships) {
    return {subteamsIn, subteamsNotIn, errors}
  }

  for (const membership of memberships.memberships) {
    const teamname = membership.teamName

    if (RPCTypes.TeamTreeMembershipStatus.ok == membership.result.s) {
      const result = membership.result.ok

      const ops = Constants.getCanPerformByID(state, result.teamID)

      const row = {
        teamID: result.teamID,
        teamname,
        memberCount: membership.result.ok.memberCount,
        joinTime: result.joinTime ?? undefined,
        canAdminister: ops.manageMembers,
      }

      const sparseMemberInfo = Constants.maybeGetSparseMembership(
        state.teams.teamDetails, state.teams.treeLoaderTeamIDToSparseMemberInfos,
        result.teamID, username,
      )

      if (sparseMemberInfo) {
        subteamsIn.push({
          role: sparseMemberInfo.type,
          key: `member:${username}:${teamname}`,
          lastActivity: 0,
          ...row
        })
      } else {
        subteamsNotIn.push(row)
      }
    } else if (RPCTypes.TeamTreeMembershipStatus.error == membership.result.s) {
      errors.push(membership)
    }
  }
  return {
    subteamsIn,
    subteamsNotIn,
    errors,
  }
}

type Extra = {title: React.ReactElement}
type Section = _Section<TeamTreeRowIn, Extra> | _Section<TeamTreeRowNotIn, Extra>

const TeamMember = (props: OwnProps) => {
  const dispatch = Container.useDispatch()
  const username = Container.getRouteProps(props, 'username', '')
  const teamID = Container.getRouteProps(props, 'teamID', Types.noTeamID)

  const isMe = username == Container.useSelector(state => state.config.username)
  const loading = Container.useSelector(state => {
    const memberships = state.teams.teamMemberToTreeMemberships.get(teamID)?.get(username)
    if (!memberships || !memberships.expectedCount) {
      return true
    }
    const got = memberships.memberships.length
    const want = memberships.expectedCount
    if (got > want) {
      logger.error(`got ${got} notifications for ${teamID}; only wanted ${want}`)
    }
    return got < want
  })

  // Load up the memberships when the page is opened
  React.useEffect(() => {
    dispatch(TeamsGen.createGetMemberSubteamDetails({teamID, username}))
  }, [teamID, username, dispatch])
  // TODO this will keep thrasing
  const {subteamsIn, subteamsNotIn, errors} = Container.useSelector(state =>
    getSubteamsInNotIn(state, teamID, username)
  )

  const [expandedSet, setExpandedSet] = React.useState(
    new Set<string>([teamID])
  )

  const makeTitle = (label) => {
      return (
        <Kb.Box2
          direction="horizontal"
          alignItems="center"
        >
          { loading && <Kb.ProgressIndicator type="Small" />}
          <Kb.Text type="BodySmallSemibold">{label}</Kb.Text>
        </Kb.Box2>
      )
  }

  const subteamsInSection: Section = {
    data: subteamsIn,
    key: 'section-subteams',
    renderItem: ({item, index}: {item: TeamTreeRowIn; index: number}) => (
      <SubteamInRow
        teamID={teamID}
        subteam={item}
        membership={item}
        idx={index}
        username={username}
        expanded={expandedSet.has(item.teamID)}
        setExpanded={newExpanded => {
          if (newExpanded) {
            expandedSet.add(item.teamID)
          } else {
            expandedSet.delete(item.teamID)
          }
          setExpandedSet(new Set([...expandedSet]))
        }}
      />
    ),
    title: makeTitle(isMe ? 'You are in:' : `${username} is in:`),
  }

  const canAddToAnyTeam = subteamsNotIn.some((x) => x.canAdminister)
  var subteamNotInTitle: string;
  if (canAddToAnyTeam && isMe) {
    subteamNotInTitle = `Add yourself to:`
  } else if (canAddToAnyTeam) {
    subteamNotInTitle = `Add ${username} to:`
  } else if (isMe) {
    subteamNotInTitle = `You are in:`
  } else {
    subteamNotInTitle = `${username} is in:`
  }
  const subteamsNotInSection = {
    data: subteamsNotIn,
    key: 'section-add-subteams',
    renderItem: ({item, index}: {item: TeamTreeRowNotIn; index: number}) => (
      <SubteamNotInRow teamID={teamID} subteam={item} idx={index} username={username} />
    ),
    title: makeTitle(subteamNotInTitle),
  }

  const sections = [
    ...(subteamsIn.length > 0 ? [subteamsInSection] : []),
    ...(subteamsNotIn.length > 0 ? [subteamsNotInSection] : []),
  ]
  return (
    <>
      { (errors.length > 0 ) && (
      <Kb.Banner color="red">
        { loading ? <Kb.ProgressIndicator type="Small" /> : <></>}
        <Kb.BannerParagraph key="teamTreeErrorHeader" bannerColor="red" content={[
          "The following teams could not be loaded. ",
          {onClick: () => dispatch(TeamsGen.createGetMemberSubteamDetails({teamID, username})), 
              text: 'Click to reload.'},
        ]} />
        <>
      {
        errors.map((error, idx) => {
          if (RPCTypes.TeamTreeMembershipStatus.error != error.result.s) {
            return (<></>)
          }

          const failedAt = [error.teamName]
          if (error.result.error.willSkipSubtree) {
            failedAt.push("its subteams")
          }
          if (error.result.error.willSkipAncestors) {
            failedAt.push("its parent teams")
          }
          var failedAtStr = ""
          if (failedAt.length > 1) {
            const last = failedAt.pop()
            failedAtStr = failedAt.join(', ') + ', and ' + last
          } else {
            failedAtStr = failedAt[0]
          }
          return (
            <Kb.BannerParagraph key={"teamTreeErrorRow" + idx.toString()} 
              bannerColor="red" content={"• " + failedAtStr} />
          )
        })
      }
      </>
    </Kb.Banner>
      )}
    <Kb.SectionList<Section>
      stickySectionHeadersEnabled={true}
      renderSectionHeader={({section}) => <Kb.SectionDivider label={section.title} />}
      sections={sections}
      keyExtractor={item => `member:${username}:${item.teamname}`}
    />
</>
  )
}

TeamMember.navigationOptions = (ownProps: OwnProps) => ({
  header: Container.isMobile
    ? () => (
        <TeamMemberHeader
          teamID={Container.getRouteProps(ownProps, 'teamID', Types.noTeamID)}
          username={Container.getRouteProps(ownProps, 'username', '')}
        />
      )
    : undefined,
  headerExpandable: true,
  headerTitle: () => (
    <TeamMemberHeader
      teamID={Container.getRouteProps(ownProps, 'teamID', Types.noTeamID)}
      username={Container.getRouteProps(ownProps, 'username', '')}
    />
  ),
})

type SubteamNotInRowProps = {
  idx: number
  subteam: TeamTreeRowNotIn
  teamID: Types.TeamID
  username: string
}
const SubteamNotInRow = (props: SubteamNotInRowProps) => {
  const dispatch = Container.useDispatch()
  const nav = Container.useSafeNavigation()
  const onAddWaitingKey = Constants.addMemberWaitingKey(props.subteam.teamID, props.username)
  const onAdd = (role: Types.TeamRoleType) =>
    dispatch(
      TeamsGen.createAddToTeam({
        sendChatNotification: true,
        teamID: props.subteam.teamID,
        users: [{assertion: props.username, role}],
      })
    )
  const openTeam = React.useCallback(
    () =>
      dispatch(
        nav.safeNavigateAppendPayload({
          path: [{props: {teamID: props.subteam.teamID}, selected: 'team'}],
        })
      ),
    [props.subteam.teamID, dispatch, nav]
  )

  const disabledRoles = Container.useSelector(state =>
    Constants.getDisabledReasonsForRolePicker(state, props.subteam.teamID, props.username)
  )

  const [role, setRole] = React.useState<Types.TeamRoleType>('writer')
  const [open, setOpen] = React.useState(false)

  const memberCount = props.subteam.memberCount ?? -1

  return (
    <Kb.Box2 direction="vertical" fullWidth={true} style={styles.rowCollapsedFixedHeight}>
      {props.idx !== 0 && <Kb.Divider />}

      {/* Placed here so that it doesn't generate any gaps */}
      <TeamDetailsSubscriber teamID={props.subteam.teamID} />

      <Kb.Box2
        direction="horizontal"
        fullWidth={true}
        alignItems="stretch"
        style={Styles.collapseStyles([styles.row, styles.contentCollapsedFixedHeight])}
      >
        <Kb.Box2
          direction="horizontal"
          alignSelf="flex-start"
          alignItems="center"
          gap="tiny"
          style={Styles.collapseStyles([
            Styles.globalStyles.flexGrow,
            styles.inviteTeamInfo,
            styles.contentCollapsedFixedHeight,
          ])}
        >
          <Kb.Avatar teamname={props.subteam.teamname} size={32} />
          <Kb.Box2
            direction="vertical"
            alignItems="flex-start"
            style={Styles.collapseStyles([
              Styles.globalStyles.flexGrow,
              styles.membershipTeamText,
              styles.contentCollapsedFixedHeight,
            ])}
          >
            <Kb.Text type="BodySemiboldLink" onClick={openTeam} style={styles.teamNameLink}>
              {props.subteam.teamname}
            </Kb.Text>
            <Kb.Text type="BodySmall">
              {memberCount.toLocaleString()} {pluralize('member', memberCount)}
            </Kb.Text>
          </Kb.Box2>
        </Kb.Box2>

        {props.subteam.canAdminister && (
        <Kb.Box2 direction="horizontal" alignSelf="center">
          <FloatingRolePicker
            onConfirm={() => {
              onAdd(role)
              setOpen(false)
            }}
            onSelectRole={setRole}
            open={open}
            onCancel={() => setOpen(false)}
            selectedRole={role}
            disabledRoles={disabledRoles}
          >
            <Kb.WaitingButton label="Add"
              onClick={() => setOpen(!open)} small={true} style={styles.inviteButton}
              waitingKey={onAddWaitingKey}
            />
          </FloatingRolePicker>
        </Kb.Box2>
      )}
      </Kb.Box2>
    </Kb.Box2>
  )
}

type SubteamInRowProps = SubteamNotInRowProps & {
  expanded: boolean
  membership: TeamTreeRowIn
  setExpanded: (b: boolean) => void
}
const SubteamInRow = (props: SubteamInRowProps) => {
  const {channelMetas, loadingChannels} = useAllChannelMetas(props.subteam.teamID)

  const dispatch = Container.useDispatch()
  const nav = Container.useSafeNavigation()
  const onAddToChannels = () =>
    dispatch(
      nav.safeNavigateAppendPayload({
        path: [
          {
            props: {teamID: props.subteam.teamID, username: props.username},
            selected: 'teamAddToChannels',
          },
        ],
      })
    )
  const onKickOutWaitingKey = Constants.removeMemberWaitingKey(props.subteam.teamID, props.username)
  const onKickOut = () =>
    dispatch(TeamsGen.createRemoveMember({teamID: props.subteam.teamID, username: props.username}))

  const openTeam = React.useCallback(
    () =>
      dispatch(
        nav.safeNavigateAppendPayload({
          path: [{props: {teamID: props.subteam.teamID}, selected: 'team'}],
        })
      ),
    [props.subteam.teamID, dispatch, nav]
  )

  const {expanded, setExpanded} = props

  const [role, setRole] = React.useState<Types.TeamRoleType>(props.membership.role)
  const [open, setOpen] = React.useState(false)
  const onChangeRole = (role: Types.TeamRoleType) => {
    dispatch(TeamsGen.createEditMembership({role, teamID: props.subteam.teamID, username: props.username}))
    setOpen(false)
  }
  const disabledRoles = Container.useSelector(state =>
    Constants.getDisabledReasonsForRolePicker(state, props.subteam.teamID, props.username)
  )
  const changingRole = Container.useAnyWaiting(
    Constants.editMembershipWaitingKey(props.subteam.teamID, props.username)
  )
  const loadingActivity = Container.useAnyWaiting(
    Constants.loadSubteamActivityWaitingKey(props.subteam.teamID, props.username)
  )

  const channelsJoined = Array.from(channelMetas)
    .map(([_, {channelname}]) => channelname)
    .join(', #')

  const rolePicker = props.subteam.canAdminister ?  (
    <FloatingRolePicker
      selectedRole={role}
      onSelectRole={setRole}
      onConfirm={onChangeRole}
      onCancel={() => setOpen(false)}
      position="bottom left"
      open={open}
      disabledRoles={disabledRoles}
    >
      <RoleButton
        containerStyle={Styles.collapseStyles([styles.roleButton, expanded && styles.roleButtonExpanded])}
        loading={changingRole}
        onClick={() => setOpen(true)}
        selectedRole={props.membership.role}
      />
    </FloatingRolePicker>
    ) : (<></>)

  return (
    <Kb.ClickableBox onClick={() => setExpanded(!expanded)}>
      <Kb.Box2 direction="vertical" fullWidth={true} style={!expanded && styles.rowCollapsedFixedHeight}>
        {props.idx !== 0 && <Kb.Divider />}

        {/* Placed here so that it doesn't generate any gaps */}
        <TeamDetailsSubscriber teamID={props.subteam.teamID} />

        <Kb.Box2 direction="horizontal" fullWidth={true} alignItems="flex-start" style={styles.row}>
          <Kb.Box2 direction="horizontal" style={Styles.collapseStyles([styles.expandIcon])}>
            <Kb.Icon type={expanded ? 'iconfont-caret-down' : 'iconfont-caret-right'} sizeType="Tiny" />
          </Kb.Box2>

          <Kb.Box2
            direction="horizontal"
            style={Styles.collapseStyles([
              Styles.globalStyles.flexGrow,
              !expanded && styles.contentCollapsedFixedHeight,
              expanded && styles.membershipExpanded,
            ])}
          >
            <Kb.Box2
              direction="vertical"
              fullWidth={true}
              alignItems="flex-start"
              gap="tiny"
              style={!expanded && styles.contentCollapsedFixedHeight}
            >
              <Kb.Box2
                direction="horizontal"
                alignSelf="flex-start"
                alignItems="center"
                gap="tiny"
                style={Styles.collapseStyles([
                  !expanded && styles.contentCollapsedFixedHeight,
                  expanded && styles.membershipContentExpanded,
                ])}
              >
                <Kb.Avatar teamname={props.subteam.teamname} size={32} />
                <Kb.Box2
                  direction="vertical"
                  alignItems="flex-start"
                  style={Styles.collapseStyles([
                    styles.membershipTeamText,
                    expanded && styles.membershipTeamTextExpanded,
                    !expanded && styles.contentCollapsedFixedHeight,
                  ])}
                >
                  <Kb.Text type="BodySemiboldLink" onClick={openTeam} style={styles.teamNameLink}>
                    {props.subteam.teamname}
                  </Kb.Text>
                  {!!props.membership.joinTime && (
                    <Kb.Text type="BodySmall">
                      Joined {formatTimeForTeamMember(props.membership.joinTime)}
                    </Kb.Text>
                  )}
                </Kb.Box2>
              </Kb.Box2>
              {expanded && Styles.isMobile && (
                <Kb.Box2 direction="horizontal" gap="tiny" alignSelf="flex-start" alignItems="center">
                  {rolePicker}
                </Kb.Box2>
              )}
              {expanded && (
                <Kb.Box2 direction="horizontal" gap="tiny" alignSelf="flex-start" alignItems="center">
                  <Kb.Icon type="iconfont-typing" sizeType="Small" color={Styles.globalColors.black_20} />
                  <Kb.Text type="BodySmall">
                    {loadingActivity
                      ? 'Loading activity...'
                      : props.membership.lastActivity
                      ? `Active ${formatTimeRelativeToNow(props.membership.lastActivity)}`
                      : 'No activity'}
                  </Kb.Text>
                </Kb.Box2>
              )}
              {expanded && (
                <Kb.Box2
                  direction="horizontal"
                  gap="tiny"
                  alignSelf="flex-start"
                  style={{justifyContent: 'center'}}
                  fullWidth={true}
                >
                  <Kb.Icon
                    type="iconfont-hash"
                    sizeType="Small"
                    color={Styles.globalColors.black_20}
                    style={styles.membershipIcon}
                  />
                  <Kb.Text
                    type="BodySmall"
                    style={Styles.globalStyles.flexOne}
                    lineClamp={4}
                    ellipsizeMode="tail"
                  >
                    {loadingChannels ? `Member of #${channelsJoined}` : 'Loading channels...'}
                  </Kb.Text>
                </Kb.Box2>
              )}
              {expanded && props.subteam.canAdminister && (
                <Kb.Box2 direction="horizontal" gap="tiny" alignSelf="flex-start">
                  <Kb.Button
                    mode="Secondary"
                    onClick={onAddToChannels}
                    label="Add to channels"
                    small={true}
                  />
                  <Kb.WaitingButton
                    mode="Secondary"
                    icon="iconfont-block"
                    type="Danger"
                    onClick={onKickOut}
                    label="Kick out"
                    small={true}
                    waitingKey={onKickOutWaitingKey}
                  />
                </Kb.Box2>
              )}

              {expanded && Styles.isMobile && <Kb.Box2 direction="horizontal" style={{height: 8}} />}
            </Kb.Box2>
          </Kb.Box2>
          {!Styles.isMobile && (
            <Kb.Box2 direction="horizontal" alignSelf={expanded ? 'flex-start' : 'center'}>
              {rolePicker}
            </Kb.Box2>
          )}
        </Kb.Box2>
      </Kb.Box2>
    </Kb.ClickableBox>
  )
}

// exported for stories
export const TeamMemberHeader = (props: Props) => {
  const {teamID, username} = props
  const dispatch = Container.useDispatch()
  const nav = Container.useSafeNavigation()

  const teamMeta = Container.useSelector(s => Constants.getTeamMeta(s, teamID))
  const teamDetails = Container.useSelector(s => Constants.getTeamDetails(s, teamID))
  const yourUsername = Container.useSelector(s => s.config.username)

  const onBack = () => dispatch(nav.safeNavigateUpPayload())
  const onChat = () =>
    dispatch(Chat2Gen.createPreviewConversation({participants: [username], reason: 'memberView'}))
  const onViewProfile = () => dispatch(ProfileGen.createShowUserProfile({username}))
  const onViewTeam = () =>
    dispatch(nav.safeNavigateAppendPayload({path: [{props: {teamID}, selected: 'team'}]}))

  const member = teamDetails.members.get(username)
  if (!member) {
    // loading? should never happen.
    logger.error('[team member view] no data! this should never happen.')
    return null
  }

  const buttons = (
    <Kb.Box2 direction="horizontal" gap="tiny" alignSelf={Styles.isMobile ? 'flex-start' : 'flex-end'}>
      <Kb.Button small={true} label="Chat" onClick={onChat} />
      <Kb.Button small={true} label="View profile" onClick={onViewProfile} mode="Secondary" />
      {username !== yourUsername && <BlockDropdown username={username} />}
    </Kb.Box2>
  )

  return (
    <Kb.Box2 direction="vertical" fullWidth={true} gap="tiny" style={styles.headerContainer}>
      {Styles.isMobile && (
        <Kb.Box2 direction="horizontal" fullWidth={true} alignItems="flex-start">
          <Kb.BackButton onClick={onBack} />
        </Kb.Box2>
      )}
      <Kb.Box2 direction="vertical" fullWidth={true} style={styles.headerContent}>
        <Kb.Box2 direction="vertical" gap="tiny" fullWidth={true}>
          <Kb.Box2
            direction="horizontal"
            alignItems="center"
            gap={Styles.isMobile ? 'tiny' : 'xtiny'}
            alignSelf="flex-start"
          >
            <Kb.Avatar size={16} teamname={teamMeta.teamname} />
            <Kb.Text
              type={Styles.isMobile ? 'BodySmallSemibold' : 'BodySmallSemiboldSecondaryLink'}
              onClick={onViewTeam}
            >
              {teamMeta.teamname}
            </Kb.Text>
          </Kb.Box2>

          <Kb.Box2
            direction="horizontal"
            gap="large"
            fullWidth={true}
            alignItems="flex-end"
            style={styles.headerTextContainer}
          >
            <Kb.Box2 direction="horizontal" gap="small">
              <Kb.Avatar size={64} username={username} />
              <Kb.Box2 direction="vertical" alignItems="flex-start" style={styles.headerText}>
                <Kb.ConnectedUsernames type="Header" usernames={username} />
                {!!member.fullName && (
                  <Kb.Text type="BodySemibold" lineClamp={1}>
                    {member.fullName}
                  </Kb.Text>
                )}
                <Kb.Text type="BodySmall">
                  Joined {member.joinTime ? formatTimeForTeamMember(member.joinTime) : 'this team'}
                </Kb.Text>
              </Kb.Box2>
            </Kb.Box2>
            {!Styles.isMobile && buttons}
          </Kb.Box2>
          {Styles.isMobile && buttons}
        </Kb.Box2>
      </Kb.Box2>
    </Kb.Box2>
  )
}

const BlockDropdown = (props: {username: string}) => {
  const dispatch = Container.useDispatch()
  const nav = Container.useSafeNavigation()
  const onBlock = () =>
    dispatch(
      nav.safeNavigateAppendPayload({
        path: [{props: {username: props.username}, selected: 'chatBlockingModal'}],
      })
    )
  const {popup, popupAnchor, showingPopup, setShowingPopup} = Kb.usePopup(getAttachmentRef => (
    <Kb.FloatingMenu
      attachTo={getAttachmentRef}
      visible={showingPopup}
      onHidden={() => setShowingPopup(false)}
      closeOnSelect={true}
      items={[{danger: true, icon: 'iconfont-remove', onClick: onBlock, title: 'Block'}]}
    />
  ))
  return (
    <>
      <Kb.Button
        small={true}
        icon="iconfont-ellipsis"
        onClick={() => setShowingPopup(true)}
        mode="Secondary"
        ref={popupAnchor}
      />
      {popup}
    </>
  )
}

const styles = Styles.styleSheetCreate(() => ({
  contentCollapsedFixedHeight: Styles.platformStyles({
    isElectron: {
      height: 48,
    },
    isMobile: {
      height: 64,
    },
  }),
  expandIcon: Styles.platformStyles({
    isElectron: {
      alignItems: 'center',
      alignSelf: 'flex-start',
      display: 'flex',
      flexShrink: 0,
      height: 48,
      justifyContent: 'center',
      padding: Styles.globalMargins.tiny,
      width: 40,
    },
    isMobile: {
      alignItems: 'center',
      alignSelf: 'flex-start',
      display: 'flex',
      flexShrink: 0,
      height: 64,
      justifyContent: 'center',
      width: 10 + Styles.globalMargins.small * 2, // 16px side paddings
    },
  }),
  headerContainer: Styles.platformStyles({
    common: {
      backgroundColor: Styles.globalColors.white,
    },
    isElectron: {
      ...Styles.desktopStyles.windowDraggingClickable,
      paddingBottom: Styles.globalMargins.small,
    },
    isMobile: {
      paddingTop: Styles.globalMargins.small,
    },
  }),
  headerContent: {
    ...Styles.padding(0, Styles.globalMargins.small),
  },
  headerText: Styles.platformStyles({
    isElectron: {
      width: 127,
    },
    isMobile: {
      flex: 1,
    },
  }),
  headerTextContainer: Styles.platformStyles({
    isMobile: {paddingBottom: Styles.globalMargins.tiny},
  }),
  reloadButton: {
    marginTop:Styles.globalMargins.tiny,
    minWidth: 56,
  },
  inviteButton: {
    minWidth: 56,
  },
  inviteTeamInfo: Styles.platformStyles({
    common: {
      paddingLeft: Styles.globalMargins.small,
    },
  }),
  membershipContentExpanded: Styles.platformStyles({
    isElectron: {
      height: 40,
      paddingTop: Styles.globalMargins.tiny,
    },
    isMobile: {
      height: 48,
      paddingTop: Styles.globalMargins.small,
    },
  }),
  membershipExpanded: Styles.platformStyles({
    isElectron: {
      paddingBottom: Styles.globalMargins.tiny,
    },
  }),
  membershipIcon: {
    flexShrink: 0,
  },
  membershipTeamText: {
    justifyContent: 'center',
  },
  membershipTeamTextExpanded: Styles.platformStyles({
    isMobile: {
      paddingTop: Styles.globalMargins.tiny,
    },
  }),
  roleButton: {
    paddingRight: 0,
  },
  roleButtonExpanded: Styles.platformStyles({
    isElectron: {
      marginTop: 12, // does not exist as an official size
    },
  }),
  row: Styles.platformStyles({
    isElectron: {
      paddingRight: Styles.globalMargins.small,
    },
    isMobile: {
      paddingRight: Styles.globalMargins.small,
    },
  }),
  rowCollapsedFixedHeight: Styles.platformStyles({
    isElectron: {
      height: 49,
    },
    isMobile: {
      flexShrink: 0,
      height: 65,
    },
  }),
  teamNameLink: {
    color: Styles.globalColors.black,
  },
}))

export default TeamMember
