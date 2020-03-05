import pandas as pdx
import numpy as np
dtype = {
    'EventType':str,'EventInfo':str,'InsertionIP':str,'Manager':str,'DetectionIP':str,'InsertionTime':str,'DetectionTime':str,'Severity':str,
'ToolAlias':str,'InferenceRule':str,'ProviderSID':str,'ExtraneousInfo':str,'UniqueID':str,'AccessGranted':str,'AccessProperties':str,'AccessRequested':str,
'AccessTarget':str,'ActionTaken':str,'AgentAddress':str,'AgentUid':str,'AgentUniqueId':str,'AgentVersion':str,'AlertActivityType':str,'ApplicationName':str,
'ApplicationVersion':str,'AuthPackage':str,'BIOSVersion':str,'BootCleaned':str,'BootSectorInfected':str,'BootSectorsScanned':str,'Category':str,
'ChangeDetails':str,'ChangeType':str,'Component':str,'ConnectionName':str,'ConnectionStatus':str,'DN':str,'Description':str,'DestinationAccount':str,
'DestinationAccountType':str,'DestinationDomain':str,'DestinationDomainID':str,'DestinationDomainType':str,'DestinationHandleID':str,
'DestinationLogonID':str,'DestinationLogonId':str,'DestinationMACAddress':str,'DestinationMachine':str,'DestinationPort':str,'DestinationProcessID':str,
'Detail':str,'DisplayName':str,'DomainMember':str,'DomainName':str,'DumpFile':str,'ElementName':str,'ElementProperty':str,'EventMessage':str,
'FailureCount':str,'FailurePoint':str,'FailureReason':str,'FastPack':str,'FeaturePackage':str,'FileHandleID':str,'FileName':str,'FilesCleaned':str,
'FilesDeleted':str,'FilesInfected':str,'FilesLeftAlone':str,'FilesQuarantined':str,'FilesScanned':str,'Filter':str,'GroupMember':str,'GroupName':str,
'GroupType':str,'ImageFile':str,'InfectedFile':str,'InfoMessage':str,'InformationName':str,'InstallOperation':str,'Interface':str,'Interfaces':str,
'InternalUserName':str,'IsThreat':str,'LicenseMaximum':str,'LicensedTo':str,'LinkName':str,'ListName':str,'Locale':str,'LogonProcess':str,'LogonType':str,
'Machine':str,'MachineType':str,'ManagerVersion':str,'Manufacturer':str,'MechanismName':str,'MechanismType':str,'MemberID':str,'MemberName':str,
'MemoryCleaned':str,'MemoryInfected':str,'Message':str,'ModType':str,'Mode':str,'Model':str,'Modification':str,'ModificationType':str,'NewPropertyValue':str,
'NewVersion':str,'ObjectHandleID':str,'ObjectName':str,'ObjectServer':str,'ObjectType':str,'OldPropertyValue':str,'OldVersion':str,'OperationID':str,
'OperationType':str,'OriginalAccount':str,'OriginalAccountID':str,'PackVersion':str,'Parameters':str,'ParentPID':str,'PatchId':str,'PeerIdentity':str,
'PolicyName':str,'Port':str,'PrimaryActionAttempt':str,'PrivilegesExercised':str,'PrivilegesUsed':str,'ProcessID':str,'ProductId':str,
'ProfileConfiguration':str,'ProfileName':str,'Protocol':str,'QueryCommand':str,'References':str,'RegistryKeyHandleID':str,'RegistryKeyName':str,
'RiskFactor':str,'ScanMessage':str,'ScanType':str,'SecondaryActionAttempt':str,'Service':str,'ServiceName':str,'ServingProcess':str,'SetCommand':str,
'SignatureName':str,'SoftwareDate':str,'SoftwarePackage':str,'SoftwareSource':str,'SourceAccount':str,'SourceDomain':str,'SourceHandleID':str,
'SourceLogonID':str,'SourceMACAddress':str,'SourceMachine':str,'SourcePort':str,'SourceProcessID':str,'StackTrace':str,'StartMessage':str,
'StatusLevel':str,'StatusMessage':str,'StopCondition':str,'StopMessage':str,'SuggestedSolution':str,'TargetMachineList':str,'ToolID':str,'TrojanName':str,
'URL':str,'Version':str,'VirusDetected':str,'VirusName':str,'WarningMessage':str
}
def columns():
    return dtype.keys()

def Dtype():
    return dtype

def SourceDestEventFreq(dataframeAll):
    temp = dataframeAll.copy()
    temp.SourceMachine = temp.SourceMachine.fillna("unknown")
    temp.DestinationMachine = temp.DestinationMachine.fillna("unknown")
    temp = temp.groupby(["SourceMachine","DestinationMachine","EventType"]).size().reset_index()
    temp.columns = ["SourceMachine","DestinationMachine","EventType","Count"]
    return temp.sort_values("Count",ascending=False)

def EventCount(dataframeAll):
    eventTypeDf = pdx.DataFrame(dataframeAll['EventType'].value_counts().reset_index())
    eventTypeDf.columns = ['Event','Count']
    return eventTypeDf.sort_values('Count',ascending=False)

def destSource(dataframeAll):
    dest_source = dataframeAll.copy()
    dest_source = pdx.DataFrame({"DetectionTime":dest_source.DetectionTime, "DestinationMachine":dest_source.DestinationMachine, "SourceMachine":dest_source.SourceMachine, "Event": dest_source.EventType,"DestinationAccount":dest_source.DestinationAccount,"SourceAccount":dest_source.SourceAccount})
    dest_source.SourceMachine = dest_source.SourceMachine.fillna("unknown")
    dest_source.DestinationMachine = dest_source.DestinationMachine.fillna("unknown")
    dest_source.DestinationAccount = dest_source.DestinationAccount("unknown")
    dest_source.SourceAccount = dest_source.SourceAccount.fillna("unknown")
    dest_source = dest_source.groupby(['SourceMachine','DestinationMachine','DestinationAccount','Event']).size().unstack()
    dest_source = dest_source.reset_index()
    return dest_source

def failedAuthentication(dataframeAll):
    dest_source = GetEvent(dataframeAll,"FailedAuthentication")
    # print(dest_source.columns)
    try:
        if  dest_source == None:
            return pdx.DataFrame(columns=['SourceMachine','DestinationAccount','DestinationMachine','FailedAuthentication']) 
    except ValueError:
        pass
    dest_source = dest_source.dropna(1,how='all')
    # dest_source = dest_source.SourceMachine.fillna("unknown",inplace=True)
    # dest_source = dest_source.DestinationMachine.fillna("unknown",inplace=True)
    # dest_source = dest_source.DestinationAccount.fillna("unknown",inplace=True)
    # faileduserAuthentication = dest_source.groupby(['SourceMachine','DestinationAccount','DestinationMachine']).size().reset_index()
    # faileduserAuthentication.columns = ['SourceMachine','DestinationAccount','DestinationMachine','FailedAuthentication']
    # faileduserAuthentication.to_csv("Dataset\\temp\\failed_Authentication.csv",index=False)
    return dest_source

def SourceEvent(dataframeAll):
    source_event = pdx.DataFrame({'SourceMachine':dataframeAll.SourceMachine,'Event':dataframeAll.EventType})
    source_event = source_event[source_event.SourceMachine!="-"]
    source_event = source_event.dropna(0)
    source_event = source_event.reset_index(drop=True)
    return source_event

def SourceEventCount(dataframeAll):
    source_event_count = SourceEvent(dataframeAll).groupby('SourceMachine').size().reset_index()
    source_event_count.columns = ['SourceMachine','Event_num']
    return source_event_count.sort_values('Event_num',ascending=False)

def EventbySource(dataframeAll):
    machine_event_count =  SourceEvent(dataframeAll).set_index(['SourceMachine','Event'])
    machine_event_count = machine_event_count.groupby(['SourceMachine','Event']).size().reset_index()
    machine_event_count.columns = ['SourceMachine','Event','Count']
    return machine_event_count.sort_values(['Count','SourceMachine'])

def GetEvent(dataframeAll, Event=None):
    if Event==None or not(Event in dataframeAll.EventType.unique()):
        return None
    else:
        if Event in dataframeAll.EventType.unique():
            return dataframeAll[dataframeAll["EventType"]==Event].reset_index(drop=True)
        else:
            return None

def activeSessions(dataframeAll):
    UserLogon = GetEvent(dataframeAll,'UserLogon')
    UserLogoff = GetEvent(dataframeAll,'UserLogoff')
    try:
        if (UserLogoff == None) or (UserLogon == None):
            return pdx.DataFrame(columns=['DestinationMachine','logon_count','logout_count','ActiveSessions'])
    except ValueError:
        pass    
    UserLogon.DestinationMachine=UserLogon.DestinationMachine.str.lower()
    UserLogoff.DestinationMachine=UserLogoff.DestinationMachine.str.lower()
        
    userlogoffbydestination = UserLogoff.groupby('DestinationMachine').size().reset_index()
    userlogonbydestination = UserLogon.groupby('DestinationMachine').size().reset_index()

    userlogoffbydestination.columns = ['DestinationMachine','logout_count']
    userlogonbydestination.columns = ['Machine','logon_count']

    userlogonbydestination = userlogonbydestination.set_index('Machine',drop=False)
    userlogoffbydestination = userlogoffbydestination.set_index('DestinationMachine',drop=False)

    sessions = userlogonbydestination.join(userlogoffbydestination,lsuffix='_caller', rsuffix='_other')

    useractivesessions = sessions.drop('DestinationMachine',axis=1)

    nologout = useractivesessions['logout_count'].isnull()

    useractivesessions= useractivesessions[~nologout]

    useractivesessions['ActiveSessions'] = np.subtract(useractivesessions.logon_count,useractivesessions.logout_count)

    useractivesessions =  useractivesessions.sort_values('ActiveSessions',ascending=False).reset_index(drop=True)

    return useractivesessions

def anonymousLogon(dataframeAll):
    UserLogon = GetEvent(dataframeAll,'UserLogon')
    try:
        if UserLogon == None:
            return pdx.DataFrame(columns=["DestinationMachine","SourceMachine","Count"])
    except ValueError:
        pass
    
    anonymous_login = UserLogon[UserLogon.DestinationAccount=='ANONYMOUS LOGON']
    anonymous_login = anonymous_login.dropna(axis=1,how='all')
    anonymous_login = anonymous_login.groupby(["DestinationMachine","SourceMachine"]).size().reset_index()
    anonymous_login.columns = ["DestinationMachine","SourceMachine","Count"]
    return anonymous_login

def MachineSessions(dataframeAll):
    MachineLogon = GetEvent(dataframeAll,'MachineLogon')
    MachineLogoff = GetEvent(dataframeAll,'MachineLogoff')
    try:
        if (MachineLogon == None) or (MachineLogoff == None):
            return pdx.DataFrame(columns=['DestinationMachine','logon_count','logout_count','ActiveSessions'])
    except  ValueError:
        pass
    MachineLogon.DestinationMachine=MachineLogon.DestinationMachine.str.lower()
    MachineLogoff.DestinationMachine=MachineLogoff.DestinationMachine.str.lower()

    machinelogoffbydestination = MachineLogoff.groupby('DestinationMachine').size().reset_index()
    machinelogonbydestination = MachineLogon.groupby('DestinationMachine').size().reset_index()

    machinelogoffbydestination.columns = ['DestinationMachine','logout_count']
    machinelogonbydestination.columns = ['Machine','logon_count']

    machinelogonbydestination = machinelogonbydestination.set_index('Machine',drop=False)
    machinelogoffbydestination = machinelogoffbydestination.set_index('DestinationMachine',drop=False)

    machinesessions = machinelogonbydestination.join(machinelogoffbydestination,lsuffix='_caller', rsuffix='_other')
    machineactivesessions = machinesessions.drop('DestinationMachine',axis=1)
    nomachinelogout = machineactivesessions['logout_count'].isnull()
    machineactivesessions= machineactivesessions[~nomachinelogout]

    machineactivesessions['ActiveSessions'] = np.subtract(machineactivesessions.logon_count,machineactivesessions.logout_count)

    machineactivesessions = machineactivesessions.sort_values('ActiveSessions',ascending=False).reset_index(drop=True)
    return machineactivesessions

def userLogonFailure(dataframeAll):
    faileduserlogon = GetEvent(dataframeAll,'UserLogonFailure')
    try:
        if faileduserlogon == None:
            return pdx.DataFrame(columns=["SourceMachine","DestinationAccount","DestinationMachine","UserLogonFailure"])
    except ValueError:
        pass    
    faileduserlogon.SourceMachine.fillna("unknown",inplace=True)

    faileduserlogon.DestinationMachine.fillna("unknown",inplace=True)
    faileduserlogon.DestinationAccount.fillna("unknown",inplace=True)

    cc = faileduserlogon.groupby(["SourceMachine","DestinationAccount","DestinationMachine"]).size().reset_index()
    cc.columns = ["SourceMachine","DestinationAccount","DestinationMachine","UserLogonFailure"]
    return cc

def userlogonSummary(dataframeAll):
    allLogons = GetEvent(dataframeAll,"UserLogon")
    try:
        if  allLogons == None:
            return pdx.DataFrame(columns=['SourceMachine','DestinationAccount','DestinationMachine','Count'])
    except ValueError:
        pass
    allLogons.DestinationMachine=allLogons.DestinationMachine.str.lower()
    allLogons.SourceMachine = allLogons.SourceMachine.fillna("unknown")
    allLogons.DestinationMachine = allLogons.DestinationMachine.fillna("unknown")
    allLogons.DestinationAccount.fillna("unknown")
    userlogon_summary = allLogons.groupby(['SourceMachine','DestinationAccount','DestinationMachine']).size().reset_index()
    userlogon_summary.columns = ['SourceMachine','DestinationAccount','DestinationMachine','Count']
    userlogon_summary = userlogon_summary.sort_values('Count',ascending=False).reset_index(drop=True)
    return userlogon_summary

def policyScopeChange(dataframeAll):
    policyscopechange_summary = GetEvent(dataframeAll,'PolicyScopeChange')
    try:
        if  policyscopechange_summary == None:
            return pdx.DataFrame(columns=['DetectionIP','DestinationDomain','DestinationAccount','Count'])
    except ValueError:
        pass
    policyscopechange_summary = policyscopechange_summary.dropna(axis=1,how='all')
    policyscopechange_summary = policyscopechange_summary.groupby(['DetectionIP','DestinationDomain','DestinationAccount']).size().reset_index()
    policyscopechange_summary.columns = ['DetectionIP','DestinationDomain','DestinationAccount','Count']
    policyscopechange_summary = policyscopechange_summary.sort_values('Count',ascending=False).reset_index(drop=True)
    return policyscopechange_summary

def preProcess(dataframeAll):
    SourceDestEventFreq(dataframeAll)
    EventCount(dataframeAll)
    failedAuthentication(dataframeAll)
    SourceEventCount(dataframeAll)
    EventbySource(dataframeAll)
    activeSessions(dataframeAll)
    anonymousLogon(dataframeAll)
    MachineSessions(dataframeAll)
    userLogonFailure(dataframeAll)
    userlogonSummary(dataframeAll)
    policyScopeChange(dataframeAll)

def mapping(key):
    maps = {
        'SourceDestEventFreq':'Source_destination_event_frequency',
        'EventCount':'event_count',
        'failedAuthentication':'failed_Authentication',
        'SourceEventCount':'source_event_count',
        'EventbySource':'event_by_source',
        'activeSessions':'user_active_sessions',
        'anonymousLogon':'anonymous_logon',
        'MachineSessions':'machine_session',
        'userLogonFailure':'user_logon_failure',
        'userlogonSummary':'user_logon_summary',
        'policyScopeChange':'policy_count'

    }
    return maps[key]

def generatereport(report,dataframeAll):
    if report == 'SourceDestEventFreq':
        return SourceDestEventFreq(dataframeAll)
    if report == 'EventCount':
        return EventCount(dataframeAll)
    if report == 'failedAuthentication':
        return failedAuthentication(dataframeAll)
    if report == 'SourceEventCount':
        return SourceEventCount(dataframeAll)
    if report == 'EventbySource':
        return EventbySource(dataframeAll)
    if report == 'activeSessions':
        return activeSessions(dataframeAll)
    if report == 'anonymousLogon':
        return anonymousLogon(dataframeAll)
    if report == 'MachineSessions':
        return MachineSessions(dataframeAll)
    if report == 'userLogonFailure':
        return userLogonFailure(dataframeAll)
    if report == 'userlogonSummary':
        return userlogonSummary(dataframeAll)
    if report == 'policyScopeChange':
        return policyScopeChange(dataframeAll)