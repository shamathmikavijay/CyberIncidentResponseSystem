
CREATE DATABASE IF NOT EXISTS cyber_incident_db;
USE cyber_incident_db;

CREATE TABLE IF NOT EXISTS Department (
    DepartmentID INT AUTO_INCREMENT PRIMARY KEY,
    DeptName VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS Employee (
    EmployeeID INT AUTO_INCREMENT PRIMARY KEY,
    Name VARCHAR(100) NOT NULL,
    Email VARCHAR(150) NOT NULL UNIQUE,
    Phone VARCHAR(20),
    Role VARCHAR(80) NOT NULL,
    DepartmentID INT NOT NULL,
    FOREIGN KEY (DepartmentID)
        REFERENCES Department(DepartmentID)
);

CREATE TABLE IF NOT EXISTS ThreatCategory (
    CategoryID INT AUTO_INCREMENT PRIMARY KEY,
    CategoryName VARCHAR(100) NOT NULL UNIQUE,
    Description TEXT
);

CREATE TABLE IF NOT EXISTS Asset (
    AssetID INT AUTO_INCREMENT PRIMARY KEY,
    AssetName VARCHAR(120) NOT NULL,
    AssetType VARCHAR(80) NOT NULL,
    IPAddress VARCHAR(45),
    Location VARCHAR(120)
);

CREATE TABLE IF NOT EXISTS Vulnerability (
    VulnerabilityID INT AUTO_INCREMENT PRIMARY KEY,
    CVE_ID VARCHAR(30) UNIQUE,
    Description TEXT NOT NULL,
    Severity ENUM('Low','Medium','High','Critical') NOT NULL
);

CREATE TABLE IF NOT EXISTS ResponseTeam (
    TeamID INT AUTO_INCREMENT PRIMARY KEY,
    TeamName VARCHAR(120) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS Incident (
    IncidentID INT AUTO_INCREMENT PRIMARY KEY,
    Title VARCHAR(200) NOT NULL,
    Description TEXT,
    DateReported DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    Status ENUM('Open','Investigating','Contained','Resolved','Closed')
        NOT NULL DEFAULT 'Open',
    SeverityLevel ENUM('Low','Medium','High','Critical') NOT NULL,
    IncidentType ENUM('Malware','Phishing','Data Breach','DDoS') NOT NULL,
    ReportedByID INT NOT NULL,
    CategoryID INT NOT NULL,
    FOREIGN KEY (ReportedByID)
        REFERENCES Employee(EmployeeID),
    FOREIGN KEY (CategoryID)
        REFERENCES ThreatCategory(CategoryID)
);

CREATE TABLE IF NOT EXISTS ResponseAction (
    ActionID INT AUTO_INCREMENT PRIMARY KEY,
    ActionDescription TEXT NOT NULL,
    ActionDate DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    Status ENUM('Pending','In Progress','Completed','Failed')
        NOT NULL DEFAULT 'Pending',
    IncidentID INT NOT NULL,
    PerformedByID INT NOT NULL,
    FOREIGN KEY (IncidentID)
        REFERENCES Incident(IncidentID),
    FOREIGN KEY (PerformedByID)
        REFERENCES Employee(EmployeeID)
);

CREATE TABLE IF NOT EXISTS IncidentReport (
    ReportID INT AUTO_INCREMENT PRIMARY KEY,
    IncidentID INT NOT NULL UNIQUE,
    GeneratedDate DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ReportContent TEXT NOT NULL,
    ApprovedByID INT,
    FOREIGN KEY (IncidentID)
        REFERENCES Incident(IncidentID),
    FOREIGN KEY (ApprovedByID)
        REFERENCES Employee(EmployeeID)
);

CREATE TABLE IF NOT EXISTS MalwareIncident (
    IncidentID INT PRIMARY KEY,
    MalwareType VARCHAR(100) NOT NULL,
    InfectedFiles INT NOT NULL DEFAULT 0,
    MalwareFamily VARCHAR(100),
    FOREIGN KEY (IncidentID)
        REFERENCES Incident(IncidentID) ON DELETE CASCADE,
    CHECK (InfectedFiles >= 0)
);

CREATE TABLE IF NOT EXISTS PhishingIncident (
    IncidentID INT PRIMARY KEY,
    PhishingURL VARCHAR(500),
    TargetEmails INT NOT NULL DEFAULT 0,
    SpoofedDomain VARCHAR(200),
    FOREIGN KEY (IncidentID)
        REFERENCES Incident(IncidentID) ON DELETE CASCADE,
    CHECK (TargetEmails >= 0)
);

CREATE TABLE IF NOT EXISTS DataBreachIncident (
    IncidentID INT PRIMARY KEY,
    RecordsCompromised INT NOT NULL DEFAULT 0,
    DataTypeExposed VARCHAR(150),
    FOREIGN KEY (IncidentID)
        REFERENCES Incident(IncidentID) ON DELETE CASCADE,
    CHECK (RecordsCompromised >= 0)
);

CREATE TABLE IF NOT EXISTS DDoSIncident (
    IncidentID INT PRIMARY KEY,
    PeakTrafficVolume DECIMAL(12,2) NOT NULL DEFAULT 0,
    SourceIPCount INT NOT NULL DEFAULT 0,
    FOREIGN KEY (IncidentID)
        REFERENCES Incident(IncidentID) ON DELETE CASCADE,
    CHECK (PeakTrafficVolume >= 0),
    CHECK (SourceIPCount >= 0)
);

CREATE TABLE IF NOT EXISTS IncidentAsset (
    IncidentID INT NOT NULL,
    AssetID INT NOT NULL,
    PRIMARY KEY (IncidentID, AssetID),
    FOREIGN KEY (IncidentID)
        REFERENCES Incident(IncidentID) ON DELETE CASCADE,
    FOREIGN KEY (AssetID)
        REFERENCES Asset(AssetID)
);

CREATE TABLE IF NOT EXISTS IncidentVulnerability (
    IncidentID INT NOT NULL,
    VulnerabilityID INT NOT NULL,
    PRIMARY KEY (IncidentID, VulnerabilityID),
    FOREIGN KEY (IncidentID)
        REFERENCES Incident(IncidentID) ON DELETE CASCADE,
    FOREIGN KEY (VulnerabilityID)
        REFERENCES Vulnerability(VulnerabilityID)
);

CREATE TABLE IF NOT EXISTS TeamAssignment (
    IncidentID INT NOT NULL,
    TeamID INT NOT NULL,
    AssignedDate DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (IncidentID, TeamID),
    FOREIGN KEY (IncidentID)
        REFERENCES Incident(IncidentID) ON DELETE CASCADE,
    FOREIGN KEY (TeamID)
        REFERENCES ResponseTeam(TeamID)
);

CREATE TABLE IF NOT EXISTS TeamMembership (
    EmployeeID INT NOT NULL,
    TeamID INT NOT NULL,
    PRIMARY KEY (EmployeeID, TeamID),
    FOREIGN KEY (EmployeeID)
        REFERENCES Employee(EmployeeID) ON DELETE CASCADE,
    FOREIGN KEY (TeamID)
        REFERENCES ResponseTeam(TeamID) ON DELETE CASCADE
);
