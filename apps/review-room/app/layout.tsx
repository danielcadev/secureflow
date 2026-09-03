import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

export const metadata: Metadata = {
  metadataBase: new URL(
    'https://secureflow-review-room.daniel-ca-pe207.chatgpt.site',
  ),
  title: 'SecureFlow Review Room',
  description:
    'An agent-native security review workspace where AI investigates structured evidence and a human owns every final decision.',
  openGraph: {
    title: 'SecureFlow Review Room',
    description: 'AI investigates. Humans decide. Evidence persists.',
    type: 'website',
    images: [
      {
        url: '/og.png',
        width: 1731,
        height: 909,
        alt: 'SecureFlow Review Room — AI investigates. Humans decide. Evidence persists.',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'SecureFlow Review Room',
    description: 'AI investigates. Humans decide. Evidence persists.',
    images: ['/og.png'],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
