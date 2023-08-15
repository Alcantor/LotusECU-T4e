<Query Kind="SQL">
  <Connection>
    <ID>7de4714c-7384-4167-8534-d4e71e2dd8c9</ID>
    <NamingServiceVersion>2</NamingServiceVersion>
    <Persist>true</Persist>
    <Provider>System.Data.SqlServerCe.3.5</Provider>
    <AttachFileName>&lt;CommonApplicationData&gt;\Omitec Ltd\Lotus Diagnostics\Data\Databases\GRP_VehicleData_Lotus_Mobile.sdf</AttachFileName>
    <Password>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAArZKwsasfXkqAcauSDX2y3AAAAAACAAAAAAAQZgAAAAEAACAAAAAj/4mU1SbUVlnxsZKVpytD5gBqCqmzm9dMTriZ9aqW0wAAAAAOgAAAAAIAACAAAACnBHQLrImj9+5/zvMyQ/BAESeXECpiooS4rPtg3MLdISAAAAB3KKWygsytPukTqhxhOngEJqMmb05YlR6LtAFTtg7BrUAAAABfmiuZYZmZUbtbUdEZD5zjErO+hO+oBTI/XQKXxyGCRT1CjFwiw2PcRs1a1Ka7BeECBjxzdkjzpiJxWtSt0Naw</Password>
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
	InformationItemInstance.DataPos,
	InformationItemInstance.DataSize,
	InformationItemInstance.DataMask
FROM
	InformationItemInstance
INNER JOIN InformationItemAbstract ON
	InformationItemInstance.FK_InformationItemAbstract_Id=InformationItemAbstract.PK_InformationItemAbstractID
INNER JOIN Request ON
	InformationItemInstance.FK_Request_Id=Request.PK_RequestID
INNER JOIN TextId ON
	InformationItemAbstract.Mnemonic=TextId.Mnemonic
INNER JOIN TextTranslation ON
	TextId.PK_TextID=TextTranslation.FK_Text_Id
WHERE
	Request.Address LIKE '22 %' AND
	InformationItemAbstract.Mnemonic LIKE 'EMS_T6_IDENT%'
ORDER BY Request.Address