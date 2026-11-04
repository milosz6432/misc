import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { ApiError } from "./api/client";
import { Layout } from "./components/Layout";
import "./index.css";
import { Dashboard } from "./pages/Dashboard";
import { IndicatorDetailPage } from "./pages/IndicatorDetail";
import { IndicatorsPage } from "./pages/Indicators";
import { InvestigationDetailPage } from "./pages/InvestigationDetail";
import { InvestigationsPage } from "./pages/Investigations";
import { LookupPage } from "./pages/Lookup";
import { ProvidersPage } from "./pages/Providers";
import { ToolsPage } from "./pages/Tools";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      // 4xx responses are deterministic: retrying only hides the message
      retry: (count, err) => !(err instanceof ApiError && err.status < 500) && count < 2,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="lookup" element={<LookupPage />} />
            <Route path="indicators" element={<IndicatorsPage />} />
            <Route path="indicators/:id" element={<IndicatorDetailPage />} />
            <Route path="investigations" element={<InvestigationsPage />} />
            <Route path="investigations/:id" element={<InvestigationDetailPage />} />
            <Route path="providers" element={<ProvidersPage />} />
            <Route path="tools" element={<ToolsPage />} />
            <Route path="*" element={<div className="p-6 text-fg-muted">Page not found.</div>} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
