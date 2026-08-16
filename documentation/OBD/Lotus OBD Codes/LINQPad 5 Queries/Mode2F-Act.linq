<Query Kind="SQL">
  <Connection>
    <ID>7de4714c-7384-4167-8534-d4e71e2dd8c9</ID>
    <NamingServiceVersion>2</NamingServiceVersion>
    <Persist>true</Persist>
    <Provider>System.Data.SqlServerCe.3.5</Provider>
    <CustomCxString>Data Source=C:\ProgramData\Omitec Ltd\Lotus Diagnostics\Data\Databases\GRP_VehicleData_Lotus_Mobile.sdf;Password=u/QSnXtt7FPc8EiZOGuv0yXbofI=</CustomCxString>
    <NoCapitalization>true</NoCapitalization>
    <DriverData>
      <LegacyMFA>false</LegacyMFA>
    </DriverData>
  </Connection>
</Query>

SELECT
	Request.Address,
	TextTranslation.Text,
	Request.Response,
	ActivationItemInstance.DataPos,
	ActivationItemInstance.DataSize,
	ActivationItemInstance.DataMask,
	CASE WHEN UnitTextTranslation.Text IS null THEN '' ELSE UnitTextTranslation.Text END AS TextUnit
FROM 
	ActivationItemInstance
INNER JOIN ActivationItemAbstract ON
	ActivationItemInstance.FK_ActivationItemAbstract_Id=ActivationItemAbstract.PK_ActivationItemAbstractID
INNER JOIN Request ON
	ActivationItemInstance.FK_Request_Id=Request.PK_RequestID
INNER JOIN TextId ON
	ActivationItemAbstract.Mnemonic=TextId.Mnemonic
INNER JOIN TextTranslation ON
	TextId.PK_TextID=TextTranslation.FK_Text_Id
LEFT JOIN TextId AS UnitTextId ON
	ActivationItemAbstract.UnitTextMnemonic=UnitTextId.Mnemonic
LEFT JOIN TextTranslation AS UnitTextTranslation ON
	UnitTextId.PK_TextID=UnitTextTranslation.FK_Text_Id
INNER JOIN EcuInstanceActivationItemInstance ON
	ActivationItemInstance.PK_ActivationItemInstanceID=EcuInstanceActivationItemInstance.FK_ActivationItemInstance_Id
INNER JOIN Ecu ON
	Ecu.PK_ID=EcuInstanceActivationItemInstance.FK_Ecu_Id
WHERE
	Ecu.Mnemonic = 'ECU_NAME_ABSTRACT_SYSTEM_LTS_EMS'
ORDER BY Request.Address