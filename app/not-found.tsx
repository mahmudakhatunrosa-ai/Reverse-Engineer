import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-neutral-950 text-neutral-100 flex flex-col items-center justify-center p-6 text-center">
      <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-400 mb-6 font-mono text-2xl font-bold">
        404
      </div>
      <h1 className="text-2xl font-bold tracking-tight mb-2">Page Not Found</h1>
      <p className="text-neutral-400 max-w-md text-sm mb-6">
        The requested resource or endpoint could not be found on the HexStrike FastMCP server dashboard.
      </p>
      <Link
        href="/"
        className="px-4 py-2 text-sm font-semibold rounded-lg bg-emerald-500 text-neutral-950 hover:bg-emerald-400 transition-colors"
      >
        Return to Dashboard
      </Link>
    </div>
  );
}
