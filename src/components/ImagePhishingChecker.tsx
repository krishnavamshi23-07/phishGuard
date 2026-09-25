import React, { useState, useEffect } from 'react';
import {
  Image as ImageIcon,
  UploadCloud,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  QrCode,
  FileText,
  Eye,
  Database,
  Trash2,
  Sparkles,
  ArrowRight,
  ArrowLeft,
  RotateCcw,
  CheckCircle2,
  ExternalLink,
  Layers,
  Copy,
  Info,
  Clock,
  Zap,
} from 'lucide-react';
import {
  analyzePhishingImage,
  getStoredRiskySignatures,
  deleteRiskySignature,
  clearRiskyVault,
  SAMPLE_IMAGES,
  type ImageScanResult,
  type RiskyImageSignature,
  type ImageSample,
} from '../services/imagePhishingEngine';

interface ImagePhishingCheckerProps {
  onNavigateToReport?: () => void;
}

export const ImagePhishingChecker: React.FC<ImagePhishingCheckerProps> = ({
  onNavigateToReport,
}) => {
  const [selectedImage, setSelectedImage] = useState<string | null>(null);
  const [selectedFileName, setSelectedFileName] = useState<string>('');
  const [selectedFileSize, setSelectedFileSize] = useState<string>('');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanResult, setScanResult] = useState<ImageScanResult | null>(null);
  const [activeStep, setActiveStep] = useState<number>(1);
  const [showVaultModal, setShowVaultModal] = useState<boolean>(false);
  const [vaultItems, setVaultItems] = useState<RiskyImageSignature[]>([]);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Load stored risky signatures on mount
  useEffect(() => {
    setVaultItems(getStoredRiskySignatures());
  }, []);

  const refreshVault = () => {
    setVaultItems(getStoredRiskySignatures());
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const sizeFormatted = `${(file.size / 1024).toFixed(1)} KB`;
    setSelectedFileName(file.name);
    setSelectedFileSize(sizeFormatted);

    const reader = new FileReader();
    reader.onload = (event) => {
      const dataUrl = event.target?.result as string;
      setSelectedImage(dataUrl);
      executeScan(dataUrl, file.name, sizeFormatted);
    };
    reader.readAsDataURL(file);
  };

  const handleSelectSample = (sample: ImageSample) => {
    setSelectedImage(sample.dataUrl);
    setSelectedFileName(sample.name);
    setSelectedFileSize('142 KB');
    executeScan(sample.dataUrl, sample.name, '142 KB');
  };

  const executeScan = async (dataUrl: string, fileName: string, fileSize: string) => {
    setIsScanning(true);
    setScanResult(null);
    setActiveStep(1);

    const result = await analyzePhishingImage(dataUrl, fileName, fileSize);
    setScanResult(result);
    setIsScanning(false);
    refreshVault();

    // If it's a cached threat hit, directly show the verdict step with the instant hit alert
    if (result.isCachedThreatHit) {
      setActiveStep(4);
    }
  };

  const handleReset = () => {
    setSelectedImage(null);
    setSelectedFileName('');
    setSelectedFileSize('');
    setScanResult(null);
    setActiveStep(1);
  };

  const handleDeleteVaultItem = (hash: string) => {
    deleteRiskySignature(hash);
    refreshVault();
  };

  const handleClearAllVault = () => {
    clearRiskyVault();
    refreshVault();
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Header with Title and Vault Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-semibold mb-2">
            <ImageIcon className="w-3.5 h-3.5" />
            <span>Visual AI &amp; Optical Threat Scanner</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Image Phishing &amp; Quishing Detector
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 max-w-xl mt-1">
            Detects fraudulent login screenshots, fake billing invoices, and malicious QR codes.
            Automatically stores risky signatures to avoid repeat attacks.
          </p>
        </div>

        {/* Risky Signatures Vault Button */}
        <button
          onClick={() => {
            refreshVault();
            setShowVaultModal(true);
          }}
          className="self-start sm:self-center px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-indigo-500/50 text-xs font-medium text-slate-200 transition-all shadow-md flex items-center space-x-2.5 cursor-pointer shrink-0"
        >
          <div className="w-6 h-6 rounded-lg bg-rose-500/20 text-rose-400 flex items-center justify-center font-bold">
            <Database className="w-3.5 h-3.5" />
          </div>
          <div className="text-left">
            <div className="text-[11px] text-slate-400 font-mono leading-none">Known Threat Vault</div>
            <div className="text-xs font-bold text-white leading-tight mt-0.5">
              {vaultItems.length} Signatures Stored
            </div>
          </div>
        </button>
      </div>

      {/* Screen 1: Intake & Upload (When no image is chosen) */}
      {!selectedImage && !isScanning && (
        <div className="space-y-6">
          {/* Upload Card */}
          <div className="rounded-2xl bg-slate-900 border-2 border-dashed border-slate-700/80 hover:border-indigo-500/60 p-8 sm:p-10 text-center transition-all group">
            <input
              type="file"
              id="image-upload-input"
              accept="image/png, image/jpeg, image/jpg, image/webp, image/svg+xml"
              onChange={handleFileUpload}
              className="hidden"
            />
            <label
              htmlFor="image-upload-input"
              className="flex flex-col items-center justify-center cursor-pointer space-y-3"
            >
              <div className="w-16 h-16 rounded-2xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-400 group-hover:scale-110 group-hover:bg-indigo-500/20 transition-all shadow-lg">
                <UploadCloud className="w-8 h-8" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-bold text-white">
                  Drop an image here or <span className="text-indigo-400 underline">browse files</span>
                </p>
                <p className="text-xs text-slate-400">
                  Supports PNG, JPG, WebP, SVG screenshots of emails, invoices, or QR codes
                </p>
              </div>
            </label>
          </div>

          {/* Quick-Click Realistic Attack Samples */}
          <div className="rounded-2xl bg-slate-900/60 border border-slate-800 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center space-x-1.5">
                <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                <span>Test with realistic threat samples:</span>
              </span>
              <span className="text-[11px] text-slate-500">1-click simulation</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {SAMPLE_IMAGES.map((sample) => (
                <button
                  key={sample.id}
                  onClick={() => handleSelectSample(sample)}
                  className={`p-3 rounded-xl border text-left transition-all cursor-pointer flex flex-col justify-between ${
                    sample.isThreat
                      ? 'bg-slate-950/80 hover:bg-rose-950/20 border-slate-800 hover:border-rose-500/40'
                      : 'bg-slate-950/80 hover:bg-emerald-950/20 border-slate-800 hover:border-emerald-500/40'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center justify-between">
                      <span
                        className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${
                          sample.isThreat
                            ? 'bg-rose-500/20 text-rose-300'
                            : 'bg-emerald-500/20 text-emerald-300'
                        }`}
                      >
                        {sample.isThreat ? 'Threat Sample' : 'Legit'}
                      </span>
                      {sample.category === 'quishing' && (
                        <QrCode className="w-3.5 h-3.5 text-indigo-400" />
                      )}
                    </div>
                    <div className="text-xs font-bold text-white pt-1">{sample.label}</div>
                    <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                      {sample.description}
                    </p>
                  </div>
                  <div className="pt-2 text-[10px] text-indigo-400 font-medium flex items-center space-x-1">
                    <span>Inspect</span>
                    <ArrowRight className="w-2.5 h-2.5" />
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Screen 2: Scanning Loading State */}
      {isScanning && (
        <div className="rounded-2xl bg-slate-900 border border-indigo-500/40 p-8 text-center space-y-4 shadow-xl animate-pulse">
          <div className="w-12 h-12 rounded-full border-4 border-indigo-500/30 border-t-indigo-400 animate-spin mx-auto" />
          <div>
            <h3 className="text-base font-bold text-white">Inspecting Visual Image Canvas...</h3>
            <p className="text-xs text-slate-400 mt-1">
              Checking Risky Signatures Vault &bull; OCR Typography &bull; Embedded QR Detection &bull; Brand Impersonation
            </p>
          </div>
        </div>
      )}

      {/* Screen 3: Progressive Layer-by-Layer Inspection Results */}
      {scanResult && !isScanning && (
        <div className="space-y-6">
          {/* Instant Cache Hit Alert (Repeated Risk Avoidance Banner) */}
          {scanResult.isCachedThreatHit && (
            <div className="rounded-xl bg-gradient-to-r from-amber-500/20 via-rose-500/20 to-amber-500/10 border border-amber-500/50 p-4 space-y-1.5 shadow-lg">
              <div className="flex items-center space-x-2 text-amber-300 font-bold text-xs uppercase tracking-wider">
                <Zap className="w-4 h-4 text-amber-400" />
                <span>Instant Threat Match: Repetitive Analysis Bypassed</span>
              </div>
              <p className="text-xs text-slate-200 leading-relaxed">
                This image matches a known malicious campaign signature previously stored in your{' '}
                <strong className="text-white">Known Threat Vault</strong> (First detected:{' '}
                <span className="font-mono text-amber-300">{scanResult.cachedAt}</span>).
                Redundant deep scanning was bypassed to instantly block the exploit.
              </p>
            </div>
          )}

          {/* Stepper Navigation Pills */}
          <div className="grid grid-cols-4 gap-2">
            {[
              { num: 1, title: 'Layer 1: Visual', desc: 'Brand Spoofing' },
              { num: 2, title: 'Layer 2: OCR', desc: 'Text & Urgency' },
              { num: 3, title: 'Layer 3: QR', desc: 'Quishing Links' },
              { num: 4, title: 'Verdict', desc: 'Vault & Remediation' },
            ].map((step) => {
              const isActive = activeStep === step.num;
              return (
                <button
                  key={step.num}
                  onClick={() => setActiveStep(step.num)}
                  className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                    isActive
                      ? 'bg-indigo-600/30 border-indigo-500 text-white shadow-md'
                      : 'bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <div className="text-[10px] uppercase font-bold text-indigo-400">
                    Step {step.num}
                  </div>
                  <div className="text-xs font-bold truncate">{step.title}</div>
                </button>
              );
            })}
          </div>

          {/* Preview + Active Layer Content Layout */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left: Image Canvas Thumbnail Preview (4 cols) */}
            <div className="lg:col-span-4 rounded-2xl bg-slate-900 border border-slate-800 p-4 space-y-3">
              <div className="text-xs font-semibold text-slate-400 flex items-center justify-between">
                <span>Inspected Asset</span>
                <span className="font-mono text-[10px] text-slate-500">{selectedFileSize}</span>
              </div>
              <div className="rounded-xl overflow-hidden bg-slate-950 border border-slate-800 flex items-center justify-center p-2 max-h-56">
                <img
                  src={scanResult.previewUrl}
                  alt="Scanned Asset"
                  className="max-h-52 w-auto object-contain rounded"
                />
              </div>
              <div className="space-y-1">
                <div className="text-xs font-mono font-medium text-slate-300 truncate" title={scanResult.fileName}>
                  {scanResult.fileName}
                </div>
                <div className="text-[10px] font-mono text-slate-500 truncate">
                  Hash: {scanResult.imageHash.substring(0, 22)}...
                </div>
              </div>

              {scanResult.storedToVault && (
                <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-[11px] text-rose-300 flex items-center space-x-1.5">
                  <Database className="w-3.5 h-3.5 shrink-0" />
                  <span>Stored in Risky Vault to prevent repetition</span>
                </div>
              )}

              <button
                onClick={handleReset}
                className="w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors flex items-center justify-center space-x-1 cursor-pointer"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Scan Another Image</span>
              </button>
            </div>

            {/* Right: Active Layer Details (8 cols) */}
            <div className="lg:col-span-8 rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-5">
              {/* STEP 1: LAYER 1 VISUAL & BRAND SPOOFING */}
              {activeStep === 1 && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="flex items-center space-x-2">
                      <Eye className="w-5 h-5 text-indigo-400" />
                      <h3 className="text-base font-bold text-white">
                        Layer 1: Visual &amp; Brand Layout Forensics
                      </h3>
                    </div>
                    <span
                      className={`text-xs font-bold px-2 py-0.5 rounded ${
                        scanResult.layers.layer1_visual.brandSpoofingDetected
                          ? 'bg-rose-500/20 text-rose-300'
                          : 'bg-emerald-500/20 text-emerald-300'
                      }`}
                    >
                      {scanResult.layers.layer1_visual.brandSpoofingDetected
                        ? 'Brand Spoofing Detected'
                        : 'Authentic / No Spoofing'}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400">
                    Inspects visual emblems, fake address bars, blurred typography artifacts, and brand logo forgery.
                  </p>

                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                    <div className="text-xs font-semibold text-slate-300">Visual Artifact Findings:</div>
                    {scanResult.layers.layer1_visual.deceptiveElements.length > 0 ? (
                      <ul className="space-y-1.5 text-xs text-rose-300">
                        {scanResult.layers.layer1_visual.deceptiveElements.map((el, idx) => (
                          <li key={idx} className="flex items-start space-x-2">
                            <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                            <span>{el}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <div className="text-xs text-emerald-400 flex items-center space-x-1.5">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>Clean graphical layout. No deceptive UI or logo spoofing found.</span>
                      </div>
                    )}
                  </div>

                  {scanResult.layers.layer1_visual.spoofedBrand && (
                    <div className="p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-xs text-indigo-300">
                      <strong>Impersonated Entity:</strong> {scanResult.layers.layer1_visual.spoofedBrand}
                    </div>
                  )}

                  <div className="pt-2 flex justify-end">
                    <button
                      onClick={() => setActiveStep(2)}
                      className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center space-x-1.5 cursor-pointer shadow-md"
                    >
                      <span>Next: Layer 2 (OCR &amp; Urgency)</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              )}

              {/* STEP 2: LAYER 2 OCR & INTENT ANALYSIS */}
              {activeStep === 2 && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="flex items-center space-x-2">
                      <FileText className="w-5 h-5 text-blue-400" />
                      <h3 className="text-base font-bold text-white">
                        Layer 2: Optical Character Recognition (OCR) &amp; Intent
                      </h3>
                    </div>
                    <span
                      className={`text-xs font-bold px-2 py-0.5 rounded ${
                        scanResult.layers.layer2_ocr_intent.urgencyTacticsFound.length > 0
                          ? 'bg-rose-500/20 text-rose-300'
                          : 'bg-emerald-500/20 text-emerald-300'
                      }`}
                    >
                      Risk Sub-score: {scanResult.layers.layer2_ocr_intent.score} / 100
                    </span>
                  </div>

                  <p className="text-xs text-slate-400">
                    Extracts embedded typography and tests for high-pressure social engineering, fraudulent hotlines, and extortion tactics.
                  </p>

                  <div className="space-y-2">
                    <span className="text-xs font-semibold text-slate-300">OCR Extracted Text:</span>
                    <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 leading-relaxed max-h-28 overflow-y-auto">
                      {scanResult.layers.layer2_ocr_intent.extractedText}
                    </div>
                  </div>

                  {scanResult.layers.layer2_ocr_intent.urgencyTacticsFound.length > 0 && (
                    <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-200 space-y-1.5">
                      <div className="font-semibold text-rose-300 flex items-center space-x-1.5">
                        <AlertTriangle className="w-4 h-4 text-rose-400" />
                        <span>High-Urgency Coercion Patterns Detected:</span>
                      </div>
                      <ul className="list-disc pl-5 space-y-0.5 text-[11px]">
                        {scanResult.layers.layer2_ocr_intent.urgencyTacticsFound.map((tactic, idx) => (
                          <li key={idx}>{tactic}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  <div className="pt-2 flex justify-between">
                    <button
                      onClick={() => setActiveStep(1)}
                      className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium flex items-center space-x-1 cursor-pointer"
                    >
                      <ArrowLeft className="w-3.5 h-3.5" />
                      <span>Back to Layer 1</span>
                    </button>
                    <button
                      onClick={() => setActiveStep(3)}
                      className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center space-x-1.5 cursor-pointer shadow-md"
                    >
                      <span>Next: Layer 3 (QR Quishing)</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              )}

              {/* STEP 3: LAYER 3 QR CODE & QUISHING */}
              {activeStep === 3 && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="flex items-center space-x-2">
                      <QrCode className="w-5 h-5 text-purple-400" />
                      <h3 className="text-base font-bold text-white">
                        Layer 3: QR Code &amp; Quishing Analysis
                      </h3>
                    </div>
                    <span
                      className={`text-xs font-bold px-2 py-0.5 rounded ${
                        scanResult.layers.layer3_qr_quishing.qrCodeDetected
                          ? 'bg-purple-500/20 text-purple-300'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {scanResult.layers.layer3_qr_quishing.qrCodeDetected
                        ? 'QR Code Identified'
                        : 'No QR Code'}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400">
                    Attackers often embed QR codes into images to evade enterprise perimeter email gateways and lure users to scan on unmanaged personal smartphones.
                  </p>

                  {scanResult.layers.layer3_qr_quishing.qrCodeDetected ? (
                    <div className="p-4 rounded-xl bg-purple-950/30 border border-purple-500/40 space-y-3">
                      <div className="text-xs font-semibold text-purple-200 flex items-center space-x-2">
                        <ShieldAlert className="w-4 h-4 text-purple-400" />
                        <span>Decoded Quishing Payload:</span>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-xs text-rose-400 break-all">
                        {scanResult.layers.layer3_qr_quishing.qrDecodedUrl || 'login-microsoft-mfa.xyz/auth'}
                      </div>
                      <p className="text-[11px] text-purple-300">
                        {scanResult.layers.layer3_qr_quishing.quishingPatternType ||
                          'QR pattern leads to an unverified third-party domain masquerading as single sign-on.'}
                      </p>
                    </div>
                  ) : (
                    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-400 flex items-center space-x-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                      <span>No QR code barcode detected within image canvas.</span>
                    </div>
                  )}

                  <div className="pt-2 flex justify-between">
                    <button
                      onClick={() => setActiveStep(2)}
                      className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium flex items-center space-x-1 cursor-pointer"
                    >
                      <ArrowLeft className="w-3.5 h-3.5" />
                      <span>Back to Layer 2</span>
                    </button>
                    <button
                      onClick={() => setActiveStep(4)}
                      className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center space-x-1.5 cursor-pointer shadow-md"
                    >
                      <span>Next: Final Verdict &amp; Vault</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              )}

              {/* STEP 4: LAYER 4 VERDICT & REPEAT AVOIDANCE VAULT */}
              {activeStep === 4 && (
                <div className="space-y-5">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div className="flex items-center space-x-2">
                      <ShieldCheck className="w-5 h-5 text-emerald-400" />
                      <h3 className="text-base font-bold text-white">
                        Multi-Layer Fusion Verdict &amp; Risk Quarantine
                      </h3>
                    </div>
                    <span
                      className={`text-xs font-bold uppercase px-3 py-1 rounded-full ${
                        scanResult.verdict === 'phishing'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                          : scanResult.verdict === 'suspicious'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      }`}
                    >
                      {scanResult.verdict === 'phishing'
                        ? 'High-Risk Phishing'
                        : scanResult.verdict === 'suspicious'
                        ? 'Suspicious Image'
                        : 'Verified Safe Image'}
                    </span>
                  </div>

                  {/* Risk Score Gauge */}
                  <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                    <div>
                      <div className="text-xs font-semibold text-slate-400">Composite Risk Score</div>
                      <div className="text-3xl font-extrabold text-white mt-0.5">
                        {scanResult.riskScore}
                        <span className="text-sm font-normal text-slate-500"> / 100</span>
                      </div>
                    </div>

                    <div className="text-right">
                      <div className="text-xs font-semibold text-slate-400">Confidence</div>
                      <div className="text-sm font-bold text-indigo-400">{scanResult.confidence}%</div>
                    </div>
                  </div>

                  {/* Vault Storage Notice (Repeated Avoidance Confirmation) */}
                  {scanResult.storedToVault && (
                    <div className="p-4 rounded-xl bg-slate-950 border border-rose-500/30 space-y-2">
                      <div className="flex items-center space-x-2 text-rose-300 font-bold text-xs uppercase tracking-wider">
                        <Database className="w-4 h-4 text-rose-400" />
                        <span>Saved to Known Risky Signatures Vault</span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        To <strong className="text-white">avoid repeated analyses</strong> and immediately protect your team, this image hash (<span className="font-mono text-indigo-300">{scanResult.imageHash.substring(0, 16)}...</span>) was stored in the threat database. Future scans of this image campaign will trigger an instant cache hit.
                      </p>
                    </div>
                  )}

                  {/* Threat Flags */}
                  {scanResult.threatFlags.length > 0 && (
                    <div className="space-y-1.5">
                      <span className="text-xs font-semibold text-slate-300">Flagged Vectors:</span>
                      <div className="space-y-1">
                        {scanResult.threatFlags.map((flag, idx) => (
                          <div
                            key={idx}
                            className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/20 text-xs text-rose-300 flex items-start space-x-2"
                          >
                            <AlertTriangle className="w-3.5 h-3.5 text-rose-400 shrink-0 mt-0.5" />
                            <span>{flag}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recommended Action Checklist */}
                  <div className="space-y-2">
                    <span className="text-xs font-semibold text-slate-300">Recommended Next Steps:</span>
                    <ul className="space-y-1.5 text-xs text-slate-400">
                      {scanResult.layers.layer4_fusion.remediationAdvice.map((adv, idx) => (
                        <li key={idx} className="flex items-start space-x-2">
                          <CheckCircle2 className="w-3.5 h-3.5 text-indigo-400 shrink-0 mt-0.5" />
                          <span>{adv}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="pt-2 flex items-center justify-between">
                    <button
                      onClick={() => setActiveStep(3)}
                      className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium flex items-center space-x-1 cursor-pointer"
                    >
                      <ArrowLeft className="w-3.5 h-3.5" />
                      <span>Back to Layer 3</span>
                    </button>

                    <button
                      onClick={handleReset}
                      className="px-5 py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-md flex items-center space-x-1.5 cursor-pointer"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>Scan Another Image</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* RISKY SIGNATURES VAULT MODAL (Stored Threat Hashes to Avoid Repetition) */}
      {showVaultModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/85 backdrop-blur-md animate-fade-in overflow-y-auto">
          <div className="max-w-2xl w-full rounded-2xl bg-slate-900 border border-slate-800 p-6 space-y-5 shadow-2xl my-8">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2.5">
                <Database className="w-5 h-5 text-rose-400" />
                <h3 className="font-bold text-white text-base">
                  Known Risky Signatures Vault
                </h3>
              </div>
              <button
                onClick={() => setShowVaultModal(false)}
                className="text-slate-400 hover:text-white cursor-pointer"
              >
                ✕
              </button>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-300 space-y-1">
              <div className="font-semibold text-white">How This Avoids Repeated Exploits:</div>
              <p className="text-slate-400 leading-relaxed">
                When an image is verified as high risk, its perceptual cryptographic hash is stored here. If that image is encountered again, deep analysis is skipped and the threat is quarantined instantaneously.
              </p>
            </div>

            <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
              {vaultItems.length === 0 ? (
                <div className="text-center py-8 text-xs text-slate-500">
                  No risky signatures stored. Scan an anomalous image or test a sample above to populate.
                </div>
              ) : (
                vaultItems.map((sig) => (
                  <div
                    key={sig.hash}
                    className="p-3.5 rounded-xl bg-slate-950 border border-rose-500/20 hover:border-rose-500/40 space-y-2 text-xs transition-colors"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="font-bold text-white text-sm flex items-center space-x-2">
                          <span>{sig.name}</span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                            Risk {sig.riskScore}/100
                          </span>
                        </div>
                        <div className="text-[11px] text-indigo-300 mt-0.5 font-medium">
                          {sig.threatType}
                        </div>
                      </div>

                      <button
                        onClick={() => handleDeleteVaultItem(sig.hash)}
                        className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-slate-900 transition-colors cursor-pointer"
                        title="Remove from vault"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-slate-400">
                      <span>First Seen: <strong className="text-slate-300 font-mono">{sig.firstSeen}</strong></span>
                      <span>&bull;</span>
                      <span>Blocked: <strong className="text-amber-300">{sig.scanCount} times</strong></span>
                      <span>&bull;</span>
                      <button
                        onClick={() => handleCopyHash(sig.hash)}
                        className="text-indigo-400 hover:text-indigo-300 font-mono text-[10px] cursor-pointer"
                      >
                        {copiedHash === sig.hash ? 'Hash Copied!' : `${sig.hash.substring(0, 16)}...`}
                      </button>
                    </div>

                    {sig.reasons.length > 0 && (
                      <div className="text-[11px] text-slate-400 bg-slate-900/60 p-2 rounded border border-slate-800/80">
                        <strong className="text-slate-300">Quarantine Reason: </strong>
                        {sig.reasons[0]}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
              {vaultItems.length > 0 ? (
                <button
                  onClick={handleClearAllVault}
                  className="text-xs text-rose-400 hover:text-rose-300 font-medium cursor-pointer"
                >
                  Clear All Signatures
                </button>
              ) : (
                <div />
              )}

              <button
                onClick={() => setShowVaultModal(false)}
                className="px-5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium cursor-pointer"
              >
                Close Vault
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
