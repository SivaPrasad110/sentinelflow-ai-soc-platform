-- CreateEnum
CREATE TYPE "AnalysisStatus" AS ENUM ('PENDING', 'COMPLETED', 'FAILED');

-- CreateEnum
CREATE TYPE "TriageSeverity" AS ENUM ('INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateTable
CREATE TABLE "IncidentAnalysis" (
    "id" TEXT NOT NULL,
    "incidentId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "status" "AnalysisStatus" NOT NULL DEFAULT 'PENDING',
    "eventId" TEXT NOT NULL,
    "workflowId" TEXT,
    "executionId" TEXT,
    "model" TEXT,
    "summary" TEXT,
    "severityAssessment" "TriageSeverity",
    "confidence" DOUBLE PRECISION,
    "evidence" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "potentialImpact" TEXT,
    "recommendedActions" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "missingInformation" TEXT[] DEFAULT ARRAY[]::TEXT[],
    "requiresHumanReview" BOOLEAN NOT NULL DEFAULT true,
    "errorMessage" TEXT,
    "rawResponse" JSONB,
    "durationMs" INTEGER,
    "triggeredById" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" TIMESTAMP(3),

    CONSTRAINT "IncidentAnalysis_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "IncidentAnalysis_eventId_key" ON "IncidentAnalysis"("eventId");

-- CreateIndex
CREATE INDEX "IncidentAnalysis_incidentId_idx" ON "IncidentAnalysis"("incidentId");

-- CreateIndex
CREATE INDEX "IncidentAnalysis_organizationId_idx" ON "IncidentAnalysis"("organizationId");

-- CreateIndex
CREATE INDEX "IncidentAnalysis_status_idx" ON "IncidentAnalysis"("status");

-- CreateIndex
CREATE INDEX "IncidentAnalysis_createdAt_idx" ON "IncidentAnalysis"("createdAt");

-- CreateIndex
CREATE INDEX "IncidentAnalysis_eventId_idx" ON "IncidentAnalysis"("eventId");

-- AddForeignKey
ALTER TABLE "IncidentAnalysis" ADD CONSTRAINT "IncidentAnalysis_incidentId_fkey" FOREIGN KEY ("incidentId") REFERENCES "Incident"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IncidentAnalysis" ADD CONSTRAINT "IncidentAnalysis_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "IncidentAnalysis" ADD CONSTRAINT "IncidentAnalysis_triggeredById_fkey" FOREIGN KEY ("triggeredById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
