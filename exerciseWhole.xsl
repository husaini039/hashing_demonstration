<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
    <xsl:output method="html" indent="yes"/>
    <xsl:template match="/">
        <html>
            <head>
                <title>Timetable</title>
            </head>
            <body>
                <h1>Semester Timetable</h1>
                <table border="1">
                    <tr>
                        <th>Course Code</th>
                        <th>Course Name</th>
                        <th>Day</th>
                        <th>Time</th>
                    </tr>
                    <xsl:for-each select="timetable/classes/class">
                        <tr>
                            <td><xsl:value-of select="courseCode"/></td>
                            <td><xsl:value-of select="courseName"/></td>
                            <td><xsl:value-of select="day"/></td>
                            <td><xsl:value-of select="time"/></td>
                        </tr>
                    </xsl:for-each>
                </table>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>
