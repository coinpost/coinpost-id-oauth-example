import { redirect } from "next/navigation";
import { validateRequest } from "~/lib/auth";

export default async function Page() {
  const { user } = await validateRequest();
  if (user) {
    return redirect("/");
  }
  return (
    <div className="container mx-auto p-4">
      <h1>Sign in</h1>
      <a href="/login/coinpost">Sign in with CoinPost</a>
    </div>
  );
}
