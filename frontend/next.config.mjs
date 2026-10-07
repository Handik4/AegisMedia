/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // genlayer-js pulls in node-flavoured crypto helpers; keep them out of the server bundle.
  experimental: { serverComponentsExternalPackages: ["genlayer-js"] },
};

export default nextConfig;
