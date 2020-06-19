/*
 * (C) Copyright 2020 Nuxeo (http://nuxeo.com/) and others.
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
 *     Anahide Tchertchian
 */
package org.nuxeo.apidoc.documentation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartDocument;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.runtime.services.config.ConfigurationService;

/**
 * Helper for XML secure content management.
 *
 * @since 11.2
 */
public class SecureXMLHelper {

    private static final Logger log = LogManager.getLogger(SecureXMLHelper.class);

    protected static final String KEYWORDS_PROPERTY = "org.nuxeo.apidoc.secure.xml.keywords";

    public static final List<String> DEFAULT_KEYWORDS = List.of("password", "Password", "secret", "apiKey");

    protected static final String WHITELISTED_KEYWORDS_PROPERTY = "org.nuxeo.apidoc.secure.xml.keywords.whitelisted";

    public static final List<String> DEFAULT_WHITELISTED_KEYWORDS = List.of("passwordField", "passwordHashAlgorithm");

    protected static final String SECRET_VALUE = "********";

    protected static final XMLInputFactory inputFactory = XMLInputFactory.newInstance();

    protected static final XMLOutputFactory outputFactory = XMLOutputFactory.newInstance();

    protected static final XMLEventFactory eventFactory = XMLEventFactory.newInstance();

    /**
     * Makes sure no passwords and similar sensitive data are embedded in the XML.
     */
    public static String secure(String xml) {
        if (StringUtils.isBlank(xml)) {
            return xml;
        }
        List<String> keywords = getKeywords();
        List<String> whitelist = getWhitelistedKeywords();
        try {
            return secureStAX(xml, keywords, whitelist);
        } catch (XMLStreamException e) {
            log.error(e, e);
            return secureRegexp(xml, keywords, whitelist);
        }
    }

    public static List<String> getKeywords() {
        return getKeywordList(KEYWORDS_PROPERTY, DEFAULT_KEYWORDS);
    }

    public static List<String> getWhitelistedKeywords() {
        return getKeywordList(WHITELISTED_KEYWORDS_PROPERTY, DEFAULT_WHITELISTED_KEYWORDS);
    }

    protected static List<String> getKeywordList(String property, List<String> defaultValue) {
        return Framework.getService(ConfigurationService.class)
                        .getString(property)
                        .map(v -> v.split("\\s*,[,\\s]*"))
                        .map(List::of)
                        .orElse(defaultValue);
    }

    public static String secureStAX(String xml, List<String> keywords, List<String> whitelist)
            throws XMLStreamException {
        // System.out.println("xml = " + xml);

        InputStream stream = new ByteArrayInputStream(xml.getBytes());
        XMLEventReader reader = inputFactory.createXMLEventReader(stream);
        OutputStream output = new ByteArrayOutputStream();
        XMLEventWriter writer = outputFactory.createXMLEventWriter(output);

        boolean skipContent = false;
        while (reader.hasNext()) {
            XMLEvent event = reader.nextEvent();
            if (skipContent && event.isCharacters()) {
                writer.add(eventFactory.createCharacters(SECRET_VALUE));
                skipContent = false;
                continue;
            }
            if (event.isStartElement()) {
                StartElement el = event.asStartElement();
                String name = el.getName().getLocalPart();
                if (matches(name, keywords, whitelist)) {
                    skipContent = true;
                }
                writer.add(eventFactory.createStartElement(el.getName(), null, null));
                Iterator<Attribute> attrIt = el.getAttributes();
                while (attrIt.hasNext()) {
                    Attribute attr = attrIt.next();
                    String attrName = attr.getName().getLocalPart();
                    String value = attr.getValue();
                    if (matches(attrName, keywords, whitelist)) {
                        // replace attribute value
                        writer.add(eventFactory.createAttribute(attrName, SECRET_VALUE));
                    } else {
                        writer.add(eventFactory.createAttribute(attrName, value));
                        if (matches(value, keywords, whitelist)) {
                            // replace node content
                            skipContent = true;
                        }
                    }
                }
            } else if (event.isStartDocument()) {
                if (((StartDocument) event).getVersion() == null) {
                    // skip it, it's been added by the reader processing
                    continue;
                } else {
                    writer.add(event);
                    writer.add(eventFactory.createCharacters("\n"));
                }
            } else {
                writer.add(event);
            }

            if (event.isEndElement()) {
                skipContent = false;
            }
        }
        writer.flush();
        writer.close();

        String all = output.toString();
        return all;
    }

    protected static boolean matches(String name, List<String> keywords, List<String> whitelist) {
        if (!whitelist.contains(name) && (keywords.stream().anyMatch(kw -> name.startsWith(kw))
                || keywords.stream().anyMatch(kw -> name.endsWith(kw)))) {
            return true;
        }
        return false;
    }

    public static String secureRegexp(String xml, List<String> keywords, List<String> whitelist) {
        String res = xml;
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
                    StringBuffer out = new StringBuffer();
                    Matcher m = Pattern.compile(pattern).matcher(res);
                    while (m.find()) {
                        String replacement;
                        if (whitelist.contains(m.group("key"))) {
                            replacement = m.group();
                        } else {
                            replacement = m.group("start") + SECRET_VALUE + m.group("end");
                        }
                        m.appendReplacement(out, replacement);
                    }
                    res = m.appendTail(out).toString();
                }
            }
        }
        return res;
    }

}
