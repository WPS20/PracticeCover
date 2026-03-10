# MaintenanceDesk 🔧

Property maintenance job booking system built with Node.js + Express.

## Features

- **Jobs** — Work orders with status tracking, action notes, 5 key dates, and communications log
- **Customers** — Managing Agents (multi-address) and Individual customers
- **Addresses** — Multiple addresses per customer, linked to jobs
- **Trades** — Trade companies with services, contact details, linked to one or more jobs
- **Dashboard** — Live stats and job status breakdown

## Job Statuses
`New` → `Booked` → `In Progress` → `Completed` → `Invoiced` → `Paid`  
Also: `On Hold`, `Cancelled`

## Running Locally

```bash
npm install
npm start
```

Open http://localhost:3000

## Deploy to Render

1. Push this project to a GitHub or GitLab repository
2. Go to [render.com](https://render.com) and create a new **Web Service**
3. Connect your repository
4. Render will auto-detect the `render.yaml` config
5. Build command: `npm install`
6. Start command: `npm start`
7. Deploy!

> **Note:** This app uses in-memory storage. Data resets on server restart.  
> For persistent data, connect a PostgreSQL database (Render offers free Postgres).

## Tech Stack

- **Backend:** Node.js + Express
- **Frontend:** Vanilla JS SPA (no build step needed)
- **Fonts:** DM Serif Display + DM Sans
