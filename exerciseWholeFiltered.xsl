<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
    <xsl:output method="html" indent="yes"/>
    <xsl:template match="/">
        <html>
            <head>
                <title>Filtered Classes</title>
            </head>
            <body>
                <h1>Classes Starting at 8:00 AM or 10:00 AM</h1>
                <ul>
                    <xsl:for-each select="timetable/classes/class[time='08:00 AM' or time='10:00 AM']">
                        <li>
                            <xsl:value-of select="courseCode"/>: 
                            <xsl:value-of select="courseName"/>
                        </li>
                    </xsl:for-each>
                </ul>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>
