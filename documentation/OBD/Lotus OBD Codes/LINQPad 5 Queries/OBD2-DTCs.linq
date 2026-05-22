<Query Kind="SQL">
  <Connection>
    <ID>7de4714c-7384-4167-8534-d4e71e2dd8c9</ID>
    <NamingServiceVersion>2</NamingServiceVersion>
    <Provider>System.Data.SqlServerCe.3.5</Provider>
    <AttachFileName>&lt;CommonApplicationData&gt;\Omitec Ltd\Lotus Diagnostics\Data\Databases\GRP_VehicleData_Lotus_Mobile.sdf</AttachFileName>
    <Password>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAArZKwsasfXkqAcauSDX2y3AAAAAACAAAAAAAQZgAAAAEAACAAAAAj/4mU1SbUVlnxsZKVpytD5gBqCqmzm9dMTriZ9aqW0wAAAAAOgAAAAAIAACAAAACnBHQLrImj9+5/zvMyQ/BAESeXECpiooS4rPtg3MLdISAAAAB3KKWygsytPukTqhxhOngEJqMmb05YlR6LtAFTtg7BrUAAAABfmiuZYZmZUbtbUdEZD5zjErO+hO+oBTI/XQKXxyGCRT1CjFwiw2PcRs1a1Ka7BeECBjxzdkjzpiJxWtSt0Naw</Password>
    <NoCapitalization>true</NoCapitalization>
    <DriverData>
      <LegacyMFA>false</LegacyMFA>
    </DriverData>
  </Connection>
  <Output>DataGrids</Output>
</Query>

SELECT
	DtcItemInstance.DtcDisplayed,
	TextTranslation.Text
FROM
	DtcItemInstance
INNER JOIN DtcItemAbstract ON
	DtcItemInstance.FK_DtcItemAbstract_Id=DtcItemAbstract.PK_DtcItemAbstractID
INNER JOIN TextId ON
	DtcItemAbstract.TextMnemonic=TextId.Mnemonic
INNER JOIN TextTranslation ON
	TextId.PK_TextID=TextTranslation.FK_Text_Id
ORDER BY DtcItemInstance.DtcDisplayed