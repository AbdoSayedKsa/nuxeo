/*
 * (C) Copyright 2011-2018 Nuxeo (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     Florent Guillaume
 */
package org.nuxeo.apidoc.documentation;

import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.nuxeo.ecm.platform.htmlsanitizer.HtmlSanitizerService;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.runtime.services.config.ConfigurationService;

/**
 * Helper to generate HTML for documentation strings.
 */
public class DocumentationHelper {

    private static final String BR = "<br/>";

    private static final String BR2 = "<br />";

    private static final String BR3 = "<br>";

    private static final String P = "<p/>";

    private static final String P2 = "<p />";

    // private static final String CODE_START = "<div class=\"code\"><pre>";
    private static final String CODE_START = "<pre><code>";

    // private static final String CODE_END = "</pre></div>";
    private static final String CODE_END = "</code></pre>";

    private static final String AUTHOR = "@author";

    private static final String SECURE_KEYWORDS_PROPERTY = "org.nuxeo.apidoc.secure.xml.keywords";

    private static final List<String> DEFAULT_SECURE_KEYWORDS = List.of("password", "Password", "secret", "apiKey");

    private static final String WHITELISTED_KEYWORDS_PROPERTY = "org.nuxeo.apidoc.secure.xml.keywords.whitelisted";

    private static final List<String> DEFAULT_WHITELISTED_KEYWORDS = List.of("passwordField", "passwordHashAlgorithm");

    private static final String SECRET_VALUE = "********";

    // utility class
    private DocumentationHelper() {
    }

    /**
     * Transforms Nuxeo extension point {@code <documentation>} content into HTML.
     * <p>
     * <ul>
     * <li>standalone newlines are turned into {@code &#60;p/&#62;}</li>
     * <li>{@code &#60;code&#62;} blocks are turned into a {@code &#60;div class="code"&#62;} with a
     * {@code &#60;pre&#62; &#60;code&#62;}</li>
     * <li>{@code @author} blocks are removed</li>
     * </ul>
     */
    public static String getHtml(String doc) {
        if (doc == null) {
            return "";
        }
        HtmlSanitizerService sanitizer = Framework.getService(HtmlSanitizerService.class);
        if (sanitizer == null && !Framework.isTestModeSet()) {
            throw new RuntimeException("Cannot find HtmlSanitizerService");
        }

        LinkedList<String> lines = new LinkedList<>();
        lines.add(P);
        boolean newline = true;
        boolean firstcode = false;
        boolean code = false;
        for (String line : doc.split("\n")) {
            if (!code) {
                line = line.trim();
                if ("".equals(line) || BR.equals(line) || BR2.equals(line) || BR3.equals(line) || P.equals(line)
                        || P2.equals(line)) {
                    if (!newline) {
                        lines.add(P);
                        newline = true;
                    }
                } else {
                    if ("<code>".equals(line)) {
                        code = true;
                        firstcode = true;
                        line = CODE_START;
                        if (!newline) {
                            line = P + line;
                        }
                        lines.add(line);
                        newline = false;
                    } else if (line.startsWith(AUTHOR)) {
                        if (!newline) {
                            lines.add(P);
                        }
                        newline = true;
                    } else {
                        lines.add(line);
                        newline = false;
                    }
                }
            } else { // code
                if ("</code>".equals(line.trim())) {
                    code = false;
                    line = CODE_END + P;
                    newline = true;
                } else {
                    line = line.replace("&", "&amp;").replace("<", "&lt;");
                }
                if (firstcode) {
                    // don't add a \n at the start of the code
                    firstcode = false;
                    line = lines.removeLast() + line;
                }
                lines.add(line);
            }
        }
        if (code) {
            lines.add(CODE_END);
        }
        String html = StringUtils.join(lines, "\n");
        if (sanitizer != null) {
            html = sanitizer.sanitizeString(html, null);
        }
        return secureXML(html);
    }

    /**
     * Makes sure no passwords are embedded in the XML.
     */
    public static String secureXML(String xml) {
        if (StringUtils.isBlank(xml)) {
            return xml;
        }
        String res = xml;
        List<String> keywords = getKeywordList(SECURE_KEYWORDS_PROPERTY, DEFAULT_SECURE_KEYWORDS);
        List<String> whitelist = getKeywordList(WHITELISTED_KEYWORDS_PROPERTY, DEFAULT_WHITELISTED_KEYWORDS);
        for (String kw : keywords) {
            if (res.contains(kw)) {
                for (String pattern : List.of(
                        // node startswith
                        String.format("(?<start><(?<key>\\w*%s)\\s*>)[^<]*(?<end></\\w*%s>)", kw, kw),
                        // node endswith
                        String.format("(?<start><(?<key>%s\\w*)\\s*>)[^<]*(?<end></%s\\w*>)", kw, kw),
                        // attributes startswith
                        String.format("(?<start>(?<key>\\w*%s)=\")[^\"]*(?<end>\")", kw),
                        String.format("(?<start>(?<key>\\w*%s)\"\\s*>)[^<]*(?<end><)", kw),
                        // attributes endswith
                        String.format("(?<start>(?<key>%s\\w*)=\")[^\"]*(?<end>\")", kw),
                        String.format("(?<start>(?<key>%s\\w*)\"\\s*>)[^<]*(?<end><)", kw))) {
                    res = secureXML(res, pattern, whitelist);
                }
            }
        }
        return res;
    }

    protected static String secureXML(String xml, String pattern, List<String> whitelist) {
        StringBuffer result = new StringBuffer();
        Matcher m = Pattern.compile(pattern).matcher(xml);
        while (m.find()) {
            String replacement;
            if (whitelist.contains(m.group("key"))) {
                replacement = m.group();
            } else {
                replacement = m.group("start") + SECRET_VALUE + m.group("end");
            }
            m.appendReplacement(result, replacement);
        }
        return m.appendTail(result).toString();
    }

    protected static List<String> getKeywordList(String property, List<String> defaultValue) {
        return Framework.getService(ConfigurationService.class)
                        .getString(property)
                        .map(v -> v.split("\\s*,[,\\s]*"))
                        .map(List::of)
                        .orElse(defaultValue);
    }

}
