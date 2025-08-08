import { prismaClient } from "db/client";

export default async function Page() {
  const users = await prismaClient.user.findMany();

  return <div>{JSON.stringify(users)}</div>;
}
