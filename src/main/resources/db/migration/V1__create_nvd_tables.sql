-- NVD CVE Data Table
-- Stores vulnerability information from the National Vulnerability Database
-- Includes CISA KEV (Known Exploited Vulnerabilities) data

CREATE TABLE nvd_cves (
    -- Core identifiers
    cve_id VARCHAR(20) PRIMARY KEY,
    source_identifier VARCHAR(255),
    vuln_status VARCHAR(50),

    -- Timestamps
    published_date TIMESTAMP NOT NULL,
    last_modified_date TIMESTAMP NOT NULL,

    -- CISA KEV fields (embedded in NVD API response)
    cisa_exploit_add DATE,
    cisa_action_due DATE,
    cisa_required_action TEXT,
    cisa_vulnerability_name VARCHAR(500),

    -- CVSS scores (multiple versions, prefer v3.1 > v3.0 > v2.0)
    cvss_v31_score DECIMAL(3,1),
    cvss_v31_severity VARCHAR(20),
    cvss_v30_score DECIMAL(3,1),
    cvss_v30_severity VARCHAR(20),
    cvss_v2_score DECIMAL(3,1),
    cvss_v2_severity VARCHAR(20),

    -- Content
    description TEXT,
    references JSONB,
    cwe_ids TEXT[],

    -- Reference metadata
    has_exploit_reference BOOLEAN DEFAULT FALSE,
    has_patch_reference BOOLEAN DEFAULT FALSE,

    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX idx_nvd_cves_published ON nvd_cves(published_date);
CREATE INDEX idx_nvd_cves_modified ON nvd_cves(last_modified_date);
CREATE INDEX idx_nvd_cves_cvss_v31 ON nvd_cves(cvss_v31_score) WHERE cvss_v31_score IS NOT NULL;

-- CISA KEV indexes
CREATE INDEX idx_nvd_cves_cisa_exploit ON nvd_cves(cisa_exploit_add) WHERE cisa_exploit_add IS NOT NULL;
CREATE INDEX idx_nvd_cves_cisa_action_due ON nvd_cves(cisa_action_due) WHERE cisa_action_due IS NOT NULL;

-- Status and weakness indexes
CREATE INDEX idx_nvd_cves_vuln_status ON nvd_cves(vuln_status);
CREATE INDEX idx_nvd_cves_cwe ON nvd_cves USING GIN(cwe_ids);

-- Reference flag indexes for quick filtering
CREATE INDEX idx_nvd_cves_has_exploit ON nvd_cves(has_exploit_reference) WHERE has_exploit_reference = TRUE;
CREATE INDEX idx_nvd_cves_has_patch ON nvd_cves(has_patch_reference) WHERE has_patch_reference = TRUE;

-- Sync Status Table
-- Tracks NVD synchronization history
CREATE TABLE nvd_sync_status (
    id SERIAL PRIMARY KEY,
    sync_type VARCHAR(20) NOT NULL, -- 'initial', 'incremental'
    last_sync_start TIMESTAMP NOT NULL,
    last_sync_end TIMESTAMP,
    last_modified_check TIMESTAMP NOT NULL,
    status VARCHAR(20) NOT NULL, -- 'running', 'completed', 'failed'
    cves_processed INT DEFAULT 0,
    cves_added INT DEFAULT 0,
    cves_updated INT DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_nvd_sync_status_created ON nvd_sync_status(created_at DESC);
CREATE INDEX idx_nvd_sync_status_type ON nvd_sync_status(sync_type, status);

-- Comments for documentation
COMMENT ON TABLE nvd_cves IS 'Stores CVE data from National Vulnerability Database including CISA KEV information';
COMMENT ON COLUMN nvd_cves.cisa_exploit_add IS 'Date CISA added this CVE to Known Exploited Vulnerabilities catalog';
COMMENT ON COLUMN nvd_cves.cisa_action_due IS 'CISA-mandated deadline for remediation';
COMMENT ON COLUMN nvd_cves.cisa_required_action IS 'Action required by CISA directive';
COMMENT ON COLUMN nvd_cves.has_exploit_reference IS 'TRUE if references include tag "Exploit"';
COMMENT ON COLUMN nvd_cves.has_patch_reference IS 'TRUE if references include tag "Patch"';

