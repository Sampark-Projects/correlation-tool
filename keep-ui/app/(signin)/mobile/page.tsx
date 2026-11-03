// page.tsx - Server Component
import { Card, Title, Text } from "@tremor/react";
import { GithubButton } from "./GithubButton";
import "../../globals.css";
import Image from "next/image";

export default function MobileLanding() {
  return (
    <main className="min-h-screen bg-gray-50 p-6">
      <Card
        className="max-w-md mx-auto flex flex-col items-center justify-center space-y-6 h-[80vh]"
        decoration="top"
        decorationColor="orange"
      >
        {/* Logo/Icon Section */}
        <Image
          src="/keep.png"
          alt="Sampark Logo"
          width={128}
          height={128}
          priority
          className="object-contain"
        />

        {/* Main Message */}
        <Title className="text-center">
          Playground Mobile Support Coming Soon!
        </Title>

        {/* Description */}
        <Text className="text-center">
          Playground is not supported on mobile devices yet, but we&apos;re
          working on it!
        </Text>

        {/* GitHub Button - Now a client component */}
        <GithubButton />

        {/* Desktop Alternative */}
        <Text className="text-sm text-gray-500 text-center">
          Want to try it now? Visit us on your desktop browser!
        </Text>
      </Card>
    </main>
  );
}
