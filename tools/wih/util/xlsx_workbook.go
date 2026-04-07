package util

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type workbookSheet struct {
	Name string
	Rows [][]string
}

func writeWorkbookFile(path string, sheets []workbookSheet) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if len(sheets) == 0 {
		return nil
	}
	if err := ensureParentDir(path); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	zipWriter := zip.NewWriter(file)
	if err = writeWorkbookEntry(zipWriter, "[Content_Types].xml", workbookContentTypesXML(len(sheets))); err != nil {
		_ = zipWriter.Close()
		return err
	}
	if err = writeWorkbookEntry(zipWriter, "_rels/.rels", workbookRootRelsXML()); err != nil {
		_ = zipWriter.Close()
		return err
	}
	if err = writeWorkbookEntry(zipWriter, "xl/workbook.xml", workbookXML(sheets)); err != nil {
		_ = zipWriter.Close()
		return err
	}
	if err = writeWorkbookEntry(zipWriter, "xl/_rels/workbook.xml.rels", workbookRelsXML(len(sheets))); err != nil {
		_ = zipWriter.Close()
		return err
	}
	if err = writeWorkbookEntry(zipWriter, "xl/styles.xml", workbookStylesXML()); err != nil {
		_ = zipWriter.Close()
		return err
	}
	for index, sheet := range sheets {
		entryPath := fmt.Sprintf("xl/worksheets/sheet%d.xml", index+1)
		if err = writeWorkbookEntry(zipWriter, entryPath, worksheetXML(sheet.Rows)); err != nil {
			_ = zipWriter.Close()
			return err
		}
	}
	return zipWriter.Close()
}

func writeWorkbookEntry(zipWriter *zip.Writer, name string, content string) error {
	writer, err := zipWriter.Create(name)
	if err != nil {
		return err
	}
	_, err = writer.Write([]byte(content))
	return err
}

func workbookContentTypesXML(sheetCount int) string {
	var builder strings.Builder
	builder.WriteString(xml.Header)
	builder.WriteString(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`)
	builder.WriteString(`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`)
	builder.WriteString(`<Default Extension="xml" ContentType="application/xml"/>`)
	builder.WriteString(`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>`)
	builder.WriteString(`<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>`)
	for i := 1; i <= sheetCount; i++ {
		builder.WriteString(fmt.Sprintf(`<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`, i))
	}
	builder.WriteString(`</Types>`)
	return builder.String()
}

func workbookRootRelsXML() string {
	return xml.Header + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`
}

func workbookXML(sheets []workbookSheet) string {
	var builder strings.Builder
	builder.WriteString(xml.Header)
	builder.WriteString(`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>`)
	for index, sheet := range sheets {
		builder.WriteString(fmt.Sprintf(`<sheet name="%s" sheetId="%d" r:id="rId%d"/>`, xmlEscapeAttr(sanitizeWorksheetName(sheet.Name, index+1)), index+1, index+1))
	}
	builder.WriteString(`</sheets></workbook>`)
	return builder.String()
}

func workbookRelsXML(sheetCount int) string {
	var builder strings.Builder
	builder.WriteString(xml.Header)
	builder.WriteString(`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`)
	for i := 1; i <= sheetCount; i++ {
		builder.WriteString(fmt.Sprintf(`<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>`, i, i))
	}
	builder.WriteString(fmt.Sprintf(`<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`, sheetCount+1))
	builder.WriteString(`</Relationships>`)
	return builder.String()
}

func workbookStylesXML() string {
	return xml.Header + `<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="1"><font><sz val="11"/><name val="Calibri"/><family val="2"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>`
}

func worksheetXML(rows [][]string) string {
	var builder strings.Builder
	builder.WriteString(xml.Header)
	builder.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	for rowIndex, row := range rows {
		builder.WriteString(fmt.Sprintf(`<row r="%d">`, rowIndex+1))
		for colIndex, value := range row {
			cellRef := excelCellRef(rowIndex+1, colIndex+1)
			builder.WriteString(fmt.Sprintf(`<c r="%s" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>`, cellRef, xmlEscapeText(value)))
		}
		builder.WriteString(`</row>`)
	}
	builder.WriteString(`</sheetData></worksheet>`)
	return builder.String()
}

func excelCellRef(row int, col int) string {
	return excelColumnName(col) + fmt.Sprintf("%d", row)
}

func excelColumnName(col int) string {
	if col < 1 {
		return "A"
	}
	var result []byte
	for col > 0 {
		col--
		result = append([]byte{byte('A' + (col % 26))}, result...)
		col /= 26
	}
	return string(result)
}

func sanitizeWorksheetName(name string, index int) string {
	text := strings.TrimSpace(name)
	if text == "" {
		text = fmt.Sprintf("Sheet%d", index)
	}
	replacer := strings.NewReplacer("\\", "_", "/", "_", "*", "_", "[", "_", "]", "_", ":", "_", "?", "_")
	text = replacer.Replace(text)
	text = strings.TrimSpace(text)
	if len(text) > 31 {
		text = text[:31]
	}
	if text == "" {
		text = fmt.Sprintf("Sheet%d", index)
	}
	return text
}

func xmlEscapeText(value string) string {
	var buffer bytes.Buffer
	_ = xml.EscapeText(&buffer, []byte(value))
	return buffer.String()
}

func xmlEscapeAttr(value string) string {
	text := xmlEscapeText(value)
	text = strings.ReplaceAll(text, `"`, "&quot;")
	return text
}

func ResolveWorkbookPath(writePath string) string {
	path := strings.TrimSpace(writePath)
	if path == "" || path == "-" {
		return path
	}
	cleaned := filepath.Clean(path)
	ext := strings.ToLower(filepath.Ext(cleaned))
	if ext == ".xlsx" {
		return cleaned
	}
	if ext == "" {
		return cleaned + ".xlsx"
	}
	return strings.TrimSuffix(cleaned, filepath.Ext(cleaned)) + ".xlsx"
}
