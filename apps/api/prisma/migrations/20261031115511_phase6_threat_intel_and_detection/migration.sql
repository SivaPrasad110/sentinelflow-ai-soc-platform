-- DropForeignKey
ALTER TABLE "IndicatorOfCompromise" DROP CONSTRAINT "IndicatorOfCompromise_incidentId_fkey";

-- AlterTable
ALTER TABLE "IndicatorOfCompromise" ADD COLUMN     "confidence" DOUBLE PRECISION DEFAULT 0.8,
ADD COLUMN     "description" TEXT,
ADD COLUMN     "firstSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "isActive" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "lastSeen" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "mitreTactics" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "mitreTechniques" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "organizationId" TEXT,
ADD COLUMN     "rawFeedData" JSONB,
ADD COLUMN     "severity" "Severity" NOT NULL DEFAULT 'MEDIUM',
ADD COLUMN     "source" TEXT DEFAULT 'MANUAL',
ADD COLUMN     "tags" TEXT[] DEFAULT ARRAY[]::TEXT[],
ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ALTER COLUMN "incidentId" DROP NOT NULL;

-- CreateTable
CREATE TABLE "ThreatFeed" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "feedUrl" TEXT NOT NULL,
    "feedType" TEXT NOT NULL DEFAULT 'CUSTOM',
    "format" TEXT NOT NULL DEFAULT 'JSON',
    "organizationId" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "lastFetchedAt" TIMESTAMP(3),
    "itemCount" INTEGER NOT NULL DEFAULT 0,
    "status" TEXT NOT NULL DEFAULT 'IDLE',
    "errorMessage" TEXT,
    "scheduleCron" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ThreatFeed_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DetectionRule" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "severity" "Severity" NOT NULL DEFAULT 'HIGH',
    "ruleType" TEXT NOT NULL DEFAULT 'PATTERN',
    "criteria" JSONB NOT NULL,
    "mitreTactic" TEXT,
    "mitreTechnique" TEXT,
    "mitreTechniqueId" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "lastTriggeredAt" TIMESTAMP(3),
    "triggerCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DetectionRule_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SecurityFinding" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "ruleId" TEXT,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "severity" "Severity" NOT NULL DEFAULT 'HIGH',
    "riskScore" DOUBLE PRECISION NOT NULL DEFAULT 50.0,
    "riskBreakdown" JSONB,
    "evidence" JSONB NOT NULL DEFAULT '{}',
    "mitreTactic" TEXT,
    "mitreTechnique" TEXT,
    "mitreTechniqueId" TEXT,
    "alertId" TEXT,
    "incidentId" TEXT,
    "fingerprint" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'NEW',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SecurityFinding_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ThreatFeed_organizationId_idx" ON "ThreatFeed"("organizationId");

-- CreateIndex
CREATE INDEX "ThreatFeed_feedType_idx" ON "ThreatFeed"("feedType");

-- CreateIndex
CREATE INDEX "ThreatFeed_status_idx" ON "ThreatFeed"("status");

-- CreateIndex
CREATE INDEX "DetectionRule_organizationId_idx" ON "DetectionRule"("organizationId");

-- CreateIndex
CREATE INDEX "DetectionRule_ruleType_idx" ON "DetectionRule"("ruleType");

-- CreateIndex
CREATE INDEX "DetectionRule_enabled_idx" ON "DetectionRule"("enabled");

-- CreateIndex
CREATE INDEX "SecurityFinding_organizationId_idx" ON "SecurityFinding"("organizationId");

-- CreateIndex
CREATE INDEX "SecurityFinding_ruleId_idx" ON "SecurityFinding"("ruleId");

-- CreateIndex
CREATE INDEX "SecurityFinding_fingerprint_idx" ON "SecurityFinding"("fingerprint");

-- CreateIndex
CREATE INDEX "SecurityFinding_status_idx" ON "SecurityFinding"("status");

-- CreateIndex
CREATE INDEX "SecurityFinding_severity_idx" ON "SecurityFinding"("severity");

-- CreateIndex
CREATE INDEX "SecurityFinding_createdAt_idx" ON "SecurityFinding"("createdAt");

-- CreateIndex
CREATE INDEX "IndicatorOfCompromise_organizationId_idx" ON "IndicatorOfCompromise"("organizationId");

-- CreateIndex
CREATE INDEX "IndicatorOfCompromise_severity_idx" ON "IndicatorOfCompromise"("severity");

-- CreateIndex
CREATE INDEX "IndicatorOfCompromise_source_idx" ON "IndicatorOfCompromise"("source");

-- CreateIndex
CREATE INDEX "IndicatorOfCompromise_isActive_idx" ON "IndicatorOfCompromise"("isActive");

-- AddForeignKey
ALTER TABLE "IndicatorOfCompromise" ADD CONSTRAINT "IndicatorOfCompromise_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IndicatorOfCompromise" ADD CONSTRAINT "IndicatorOfCompromise_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ThreatFeed" ADD CONSTRAINT "ThreatFeed_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DetectionRule" ADD CONSTRAINT "DetectionRule_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityFinding" ADD CONSTRAINT "SecurityFinding_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SecurityFinding" ADD CONSTRAINT "SecurityFinding_ruleId_fkey" FOREIGN KEY ("ruleId") REFERENCES "DetectionRule"("id") ON DELETE SET NULL ON UPDATE CASCADE;
