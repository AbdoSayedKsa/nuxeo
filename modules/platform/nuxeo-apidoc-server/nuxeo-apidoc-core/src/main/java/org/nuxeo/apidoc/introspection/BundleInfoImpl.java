/*
 * (C) Copyright 2006-2010 Nuxeo SA (http://nuxeo.com/) and others.
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
 *     Bogdan Stefanescu
 *     Thierry Delprat
 */
package org.nuxeo.apidoc.introspection;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.nuxeo.apidoc.api.BaseNuxeoArtifact;
import org.nuxeo.apidoc.api.BundleGroup;
import org.nuxeo.apidoc.api.BundleInfo;
import org.nuxeo.apidoc.api.ComponentInfo;
import org.nuxeo.ecm.core.api.Blob;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class BundleInfoImpl extends BaseNuxeoArtifact implements BundleInfo {

    protected final String bundleId;

    protected final List<ComponentInfo> components = new ArrayList<>();

    protected String fileName;

    protected String manifest;

    protected String location;

    /** @since 11.1 */
    protected final List<String> requirements = new ArrayList<>();

    protected String groupId;

    protected String artifactId;

    protected String artifactVersion;

    protected BundleGroup bundleGroup;

    protected Blob readme;

    protected Blob parentReadme;

    /** @since 11.1 */
    protected Long deploymentOrder;

    /** @since 11.1 */
    protected final List<String> packages = new ArrayList<>();

    @JsonCreator
    private BundleInfoImpl(@JsonProperty("bundleId") String bundleId, @JsonProperty("fileName") String fileName,
            @JsonProperty("manifest") String manifest, @JsonProperty("requirements") List<String> requirements,
            @JsonProperty("groupId") String groupId, @JsonProperty("artifactId") String artifactId,
            @JsonProperty("artifactVersion") String artifactVersion,
            @JsonProperty("bundleGroup") BundleGroup bundleGroup, @JsonProperty("readme") Blob readme,
            @JsonProperty("parentReadme") Blob parentReadme, @JsonProperty("location") String location) {
        this.bundleId = bundleId;
        this.fileName = fileName;
        this.manifest = manifest;
        if (requirements != null) {
            this.requirements.addAll(requirements);
        }
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.artifactVersion = artifactVersion;
        this.bundleGroup = bundleGroup;
        this.readme = readme;
        this.parentReadme = parentReadme;
        this.location = location;
        // components will be handled by json managed reference
    }

    public BundleInfoImpl(String bundleId) {
        this.bundleId = bundleId;
    }

    @Override
    public BundleGroup getBundleGroup() {
        return bundleGroup;
    }

    public void setBundleGroup(BundleGroup bundleGroup) {
        this.bundleGroup = bundleGroup;
    }

    @Override
    public List<ComponentInfo> getComponents() {
        return Collections.unmodifiableList(components);
    }

    public void addComponent(ComponentInfoImpl component) {
        components.add(component);
    }

    @Override
    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    @Override
    public String getBundleId() {
        return bundleId;
    }

    @Override
    public List<String> getRequirements() {
        return Collections.unmodifiableList(requirements);
    }

    public void setRequirements(List<String> requirements) {
        this.requirements.clear();
        if (requirements != null) {
            this.requirements.addAll(requirements);
        }
    }

    @Override
    public List<String> getPackages() {
        return packages.stream()
                       .sorted()
                       .collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
    }

    public void setPackages(List<String> packages) {
        this.packages.clear();
        if (packages != null) {
            this.packages.addAll(packages);
        }
    }

    @Override
    public String getManifest() {
        return manifest;
    }

    public void setManifest(String manifest) {
        this.manifest = manifest;
    }

    @Override
    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    @Override
    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    @Override
    public String getArtifactId() {
        return artifactId;
    }

    public void setArtifactId(String artifactId) {
        this.artifactId = artifactId;
    }

    @Override
    public String getArtifactVersion() {
        return artifactVersion;
    }

    public void setArtifactVersion(String artifactVersion) {
        this.artifactVersion = artifactVersion;
    }

    @Override
    public String getId() {
        return bundleId;
    }

    @Override
    public String getVersion() {
        return artifactVersion;
    }

    @Override
    public String getArtifactType() {
        return TYPE_NAME;
    }

    @Override
    public String getHierarchyPath() {
        return getBundleGroup().getHierarchyPath() + "/" + getId();
    }

    @Override
    public Blob getReadme() {
        return readme;
    }

    @Override
    public Blob getParentReadme() {
        return parentReadme;
    }

    public void setReadme(Blob readme) {
        this.readme = readme;
    }

    public void setParentReadme(Blob parentReadme) {
        this.parentReadme = parentReadme;
    }

    @Override
    public Long getDeploymentOrder() {
        return deploymentOrder;
    }

    @Override
    public void setDeploymentOrder(Long deploymentOrder) {
        this.deploymentOrder = deploymentOrder;
    }

}
