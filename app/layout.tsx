import type {Metadata} from 'next';
import './globals.css'; // Global styles

export const metadata: Metadata = {
  title: 'HexStrike AI FastMCP Server',
  description: 'Production FastMCP server for HexStrike AI reverse engineering & security toolkit with 24/7 Render deployment guides, live testing console, and Claude MCP configs.',
  openGraph: {
    title: 'HexStrike AI FastMCP Server',
    description: 'Production FastMCP server for HexStrike AI reverse engineering & security toolkit with 24/7 Render deployment guides, live testing console, and Claude MCP configs.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'HexStrike AI FastMCP Server',
    description: 'Production FastMCP server for HexStrike AI reverse engineering & security toolkit with 24/7 Render deployment guides, live testing console, and Claude MCP configs.',
  },
};

export default function RootLayout({children}: {children: React.ReactNode}) {
  return (
    <html lang="en">
      <body suppressHydrationWarning>{children}</body>
    </html>
  );
}
