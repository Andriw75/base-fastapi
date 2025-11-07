from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def main():
    return {"ping":"pong"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app,host='192.168.68.96',port=2000)

