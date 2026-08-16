<Query Kind="SQL">
  <Connection>
    <ID>7de4714c-7384-4167-8534-d4e71e2dd8c9</ID>
    <NamingServiceVersion>2</NamingServiceVersion>
    <Provider>System.Data.SqlServerCe.3.5</Provider>
    <CustomCxString>Data Source=C:\ProgramData\Omitec Ltd\Lotus Diagnostics\Data\Databases\GRP_VehicleData_Lotus_Mobile.sdf;Password=u/QSnXtt7FPc8EiZOGuv0yXbofI=</CustomCxString>
    <NoCapitalization>true</NoCapitalization>
    <DriverData>
      <LegacyMFA>false</LegacyMFA>
    </DriverData>
  </Connection>
  <Output>DataGrids</Output>
</Query>

-- One row per DTC instance and referencing ECU set, ordered by an explicit
-- priority: the EMS engine sets first with the T6/V6 variants ahead, so their
-- bank-qualified texts win if the sets ever diverge (in the current DB all
-- four share DtcSet 5 and emit the same rows), then TCU; every other set
-- (airbag, TPMS, ABS, SYSTEM_UNKNOWN) shares the lowest rank, with no defined
-- order among them.
-- The EMS rank keeps SYSTEM_UNKNOWN's generic list - whose texts for
-- P0010-P0024 are mis-mapped (they belong to P0001-P000F) - away from the
-- engine codes; codes only that list defines (e.g. P0201-P0205, P0237/P0238,
-- P0340, P0627) still get their (correct) generic text. Every instance is
-- referenced by at least one set, so the LEFT JOINs produce no NULL rows.
-- The Ghidra import (OBD2CodeConfiguration.java) keeps the FIRST text per code.
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
INNER JOIN DtcSetItem ON
	DtcSetItem.DtcItemInstanceId=DtcItemInstance.PK_ID
INNER JOIN Ecu ON
	Ecu.DtcSetId=DtcSetItem.DtcSetId
ORDER BY
	CASE Ecu.Mnemonic
		WHEN 'ECU_NAME_ABSTRACT_SYSTEM_LTS_EMS_T6'    THEN  0
		WHEN 'ECU_NAME_ABSTRACT_SYSTEM_LTS_EMS_T6_S4' THEN  1
		WHEN 'ECU_NAME_ABSTRACT_SYSTEM_LTS_EMS'       THEN  2
		WHEN 'ECU_NAME_ABSTRACT_SYSTEM_LTS_EMS_KLINE' THEN  3
		WHEN 'ECU_NAME_ABSTRACT_SYSTEM_LTS_TCU'       THEN  4
		ELSE 5
	END,
	DtcItemInstance.DtcDisplayed
