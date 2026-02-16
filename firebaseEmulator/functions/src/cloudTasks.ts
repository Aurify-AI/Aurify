import { CloudTasksClient, protos } from "@google-cloud/tasks";

const project = process.env.PROJECT_ID as string;
const queue = process.env.QUEUE_NAME as string;
const location = process.env.LOCATION as string;
const url = process.env.CLOUD_FUNCTION_BASE_URL as string;

export async function queuePostAtSpecifiedTime(time: Date, functionName: String) {
  console.log(project, queue, location, url);
  
  const client = new CloudTasksClient();

  const parent = client.queuePath(project, location, queue);

  const task: protos.google.cloud.tasks.v2.ITask = {
    httpRequest: {
      httpMethod: "POST",
      url: `${url}/${functionName}`,
      headers: {
        "Content-Type": "application/json",
      },
      //   body: Buffer.from(JSON.stringify(payload)).toString("base64")
    },
    scheduleTime: {
      seconds: Math.floor(time.getTime() / 1000),
    },
  };
  // Send create task request.
  await client.createTask({ parent, task });
}
