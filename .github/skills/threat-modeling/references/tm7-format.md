# TM7 XML Format Reference

TM7 is the XML file format used by the [Microsoft Threat Modeling Tool](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool). This document describes the XML structure for developers working with the CLI.

## Namespaces

| Prefix | URI | Purpose |
|--------|-----|---------|
| (default) | `http://schemas.datacontract.org/2004/07/ThreatModeling.Model` | Top-level model elements |
| `a:` | `http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase` | Knowledge base, threat types, element types |
| `b:` | `http://schemas.microsoft.com/2003/10/Serialization/Arrays` | Serialization arrays (KeyValuePairs, lists) |
| `d:` | `http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts` | Abstract element types (Guid, Properties, etc.) |

## Top-Level Structure

```xml
<ThreatModel>
  <DrawingSurfaceList>         <!-- Visual diagrams (DFD pages) -->
    <DrawingSurfaceModel>
      <Borders>                <!-- Elements: Processes, Data Stores, External Interactors, Trust Boundaries -->
      <Lines>                  <!-- Data Flows and line-type Trust Boundaries -->
      <Header>                 <!-- Diagram name -->
      <Zoom>                   <!-- Zoom level -->
    </DrawingSurfaceModel>
  </DrawingSurfaceList>
  <MetaInformation>            <!-- Model metadata -->
    <ThreatModelName>
    <Owner>
    <Reviewer>
    <HighLevelSystemDescription>
    <Assumptions>
    <ExternalDependencies>
    <Contributors>
  </MetaInformation>
  <Notes>                      <!-- User notes -->
  <ThreatInstances>            <!-- Generated/custom threats -->
  <ThreatGenerationEnabled>    <!-- true/false -->
  <Validations>                <!-- Validation results -->
  <Version>                    <!-- Format version (2.0) -->
  <KnowledgeBase>              <!-- Element types, threat generation rules -->
</ThreatModel>
```

## Element Types (GenericTypeId)

| GenericTypeId | Description | Visual Shape |
|---------------|-------------|--------------|
| `GE.EI` | External Interactor | Rectangle |
| `GE.P` | Process | Circle/Rounded Rectangle |
| `GE.DS` | Data Store | Parallel lines |
| `GE.DF` | Data Flow | Arrow/connector |
| `GE.TB` | Trust Boundary (rectangular) | Dashed rectangle |
| `GE.TB.L` | Trust Boundary (line) | Dashed line |
| `GE.S` | Drawing Surface | Container |

## Common TypeIds

| TypeId | GenericType | Description |
|--------|------------|-------------|
| `SE.P.TMCore.WebApp` | GE.P | Web Application |
| `SE.P.TMCore.WebServer` | GE.P | Web Server |
| `SE.P.TMCore.WCF` | GE.P | WCF Service |
| `SE.DS.TMCore.SQL` | GE.DS | SQL Database |
| `SE.DS.TMCore.NoSQL` | GE.DS | NoSQL Database |
| `SE.DS.TMCore.FileSystem` | GE.DS | File System |
| `SE.EI.TMCore.Browser` | GE.EI | Web Browser |
| `SE.EI.TMCore.AuthProvider` | GE.EI | Authentication Provider |
| `SE.DF.TMCore.HTTP` | GE.DF | HTTP Data Flow |
| `SE.DF.TMCore.HTTPS` | GE.DF | HTTPS Data Flow |
| `SE.DF.TMCore.ALPC` | GE.DF | Local Procedure Call |
| `SE.DF.TMCore.IPsec` | GE.DF | IPsec Data Flow |
| `SE.TB.L.TMCore.Internet` | GE.TB | Internet Trust Boundary |
| `SE.TB.L.TMCore.Machine` | GE.TB | Machine Trust Boundary |

## Element Properties

Each element has a `Properties` collection of typed attributes:

```xml
<Properties>
  <anyType xsi:type="b:StringDisplayAttribute">
    <DisplayName>Name</DisplayName>
    <Name/>
    <Value xsi:type="c:string">My Element</Value>
  </anyType>
  <anyType xsi:type="b:BooleanDisplayAttribute">
    <DisplayName>Out Of Scope</DisplayName>
    <Name>71f3d9aa-b8ef-4e54-8126-607a1d903103</Name>
    <Value xsi:type="c:boolean">false</Value>
  </anyType>
  <anyType xsi:type="b:ListDisplayAttribute">
    <DisplayName>Authenticates Itself</DisplayName>
    <Name>authenticatesItself</Name>
    <Value xsi:type="a:ArrayOfstring">
      <string>Not Applicable</string>
      <string>No</string>
      <string>Yes</string>
    </Value>
    <SelectedIndex>0</SelectedIndex>
  </anyType>
</Properties>
```

## Threat Instance Structure

```xml
<KeyValueOfstringThreatpc_P0_PhOB>
  <Key>{ThreatTypeId}{SourceGuid}{FlowGuid}{TargetGuid}</Key>
  <Value>
    <ChangedBy>username</ChangedBy>
    <DrawingSurfaceGuid>...</DrawingSurfaceGuid>
    <FlowGuid>...</FlowGuid>
    <Id>25</Id>
    <InteractionKey>sourceGuid:flowGuid:targetGuid</InteractionKey>
    <ModifiedAt>2024-01-01T00:00:00Z</ModifiedAt>
    <Priority>High</Priority>
    <Properties>
      <KeyValueOfstringstring>
        <Key>Title</Key>
        <Value>SQL Injection</Value>
      </KeyValueOfstringstring>
      <KeyValueOfstringstring>
        <Key>UserThreatCategory</Key>
        <Value>Tampering</Value>
      </KeyValueOfstringstring>
      <KeyValueOfstringstring>
        <Key>UserThreatDescription</Key>
        <Value>...</Value>
      </KeyValueOfstringstring>
      <!-- Custom properties use GUIDs as keys -->
    </Properties>
    <SourceGuid>...</SourceGuid>
    <State>NeedsInvestigation</State>
    <TargetGuid>...</TargetGuid>
    <TypeId>T7</TypeId>
  </Value>
</KeyValueOfstringThreatpc_P0_PhOB>
```

## Threat States

| XML Value | Display Name |
|-----------|-------------|
| `NeedsInvestigation` | Needs Investigation |
| `NotApplicable` | Not Applicable |
| `Mitigated` | Mitigated |
| `NotStarted` | Not Started |
| `AutoGenerated` | Auto Generated |

## STRIDE Categories

| Code | Full Name |
|------|-----------|
| S | Spoofing |
| T | Tampering |
| R | Repudiation |
| I | Information Disclosure |
| D | Denial of Service |
| E | Elevation of Privilege |

## Known Property GUIDs

| GUID | Label |
|------|-------|
| `71f3d9aa-b8ef-4e54-8126-607a1d903103` | Out Of Scope |
| `752473b6-52d4-4776-9a24-202153f7d579` | Reason For Out Of Scope |
| `f9e02b87-2914-407e-bd11-97353ef43162` | Risk |
| `941f9317-678b-4a2e-807a-a820331bec42` | Team |
| `44490cdf-6399-4291-9bde-03dca6f03c11` | Mitigation |
| `bc9c6e2a-15d0-4863-9cac-589e51e4ca1e` | Priority |
