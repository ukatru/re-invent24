from dagster import Definitions, load_assets_from_modules
from dagster_azure.blob import (
    AzureBlobStorageResource,
    AzureBlobStorageKeyCredential,
    AzureBlobStorageDefaultCredential
)
from dagster_azure.adls2 import ADLS2Resource, ADLS2SASToken

from .import assets, azure_storage, azure_fs, azure_file_system

all_assets = load_assets_from_modules([assets, azure_storage,azure_fs,azure_file_system])

defs = Definitions(
    assets=all_assets,
    resources={
        "azure_blob_storage": AzureBlobStorageResource(
            account_url="https://mydagsterpocstg.blob.core.windows.net/",
            credential=AzureBlobStorageKeyCredential(key="Ba187/pVE8XW9bc+xs9leOxB7534CIQebRchQJzTP7zKA07OJPVAovz+CE7WISTiMf5+iDWqiIOo+AStaWTc0Q==")
        ),
        "adls2": ADLS2Resource(
            storage_account="mydagsterpocstg",
            credential=ADLS2SASToken(token="Ba187/pVE8XW9bc+xs9leOxB7534CIQebRchQJzTP7zKA07OJPVAovz+CE7WISTiMf5+iDWqiIOo+AStaWTc0Q=="),
        )
    }

)


###################3
from azure.storage.fileshare import ShareServiceClient, ShareClient, ShareDirectoryClient, ShareFileClient
import pandas as pd
import io
from dagster import asset

@asset
def azure_read_file_share():
    account_url="https://mydagsterpocstg.blob.core.windows.net/"
    credential="Ba187/pVE8XW9bc+xs9leOxB7534CIQebRchQJzTP7zKA07OJPVAovz+CE7WISTiMf5+iDWqiIOo+AStaWTc0Q=="
    service_client = ShareServiceClient(account_url=account_url, credential=credential)
    share_name = "mypocfs"
    share_client = service_client.get_share_client(share_name)
    print(share_client)


###############
from dagster import Definitions, asset, job, op
from dagster_azure.adls2 import ADLS2Resource, ADLS2SASToken
import pandas as pd


@asset
def azure_fs(adls2: ADLS2Resource):
    file_client = adls2.adls2_client.get_file_client(file_system="mypocfs", file_path="poc/0054ca61-6f69-4048-9c81-0c6cc1cfaf52.txt")
    file_client.download_file()


@asset
def azure_read_dl_file():
    SAS_URL = "https://mydagsterpocstg.file.core.windows.net/mypocfs/poc/0054ca61-6f69-4048-9c81-0c6cc1cfaf52.txt?sp=r&st=2025-05-11T03:33:20Z&se=2025-05-18T03:33:00Z&spr=https&sv=2024-11-04&sig=zmTUf%2Bx9S7NQchsJ37ug1Gfr7THmFA%2BXxFj7DAsjzak%3D&sr=f"
    df = pd.read_csv(SAS_URL)
    f = open(SAS_URL,'r',encoding = 'utf-8')
    print(f.readline())

@asset
def azure_create_file(adls2: ADLS2Resource):
    df = pd.DataFrame({"column1": [1, 2, 3], "column2": ["A", "B", "C"]})

    csv_data = df.to_csv(index=False)

    file_client = adls2.adls2_client.get_file_client(
        "dagster", "poc/my_dataframe.csv"
    )
    file_client.upload_data(csv_data, overwrite=True)




##########3
from dagster import asset, MaterializeResult, MetadataValue
from dagster_azure.blob import (
    AzureBlobStorageResource,
    AzureBlobStorageKeyCredential,
    AzureBlobStorageDefaultCredential
)
import os
import uuid

@asset
def azure_storage_write_file(azure_blob_storage: AzureBlobStorageResource):
    # Create a local directory to hold blob data
    local_path = "/Users/ukatru/src/dagster/data"
    #os.mkdir(local_path)

    # Create a file in the local data directory to upload and download
    local_file_name = str(uuid.uuid4()) + ".txt"
    upload_file_path = os.path.join(local_path, local_file_name)
    # Write text to the file
    file = open(file=upload_file_path, mode='w')
    file.write("Hello, World!")
    file.close()
    with azure_blob_storage.get_client() as blob_storage_client:
        # Create a blob client using the local file name as the name for the blob
        blob_client = blob_storage_client.get_blob_client(container='dagster', blob=local_file_name)

    print("\nUploading to Azure Storage as blob:\n\t" + local_file_name)

    # Upload the created file
    with open(file=upload_file_path, mode="rb") as data:
        blob_client.upload_blob(data)


#########
from azure.storage.fileshare import ShareServiceClient
ConnectionString="DefaultEndpointsProtocol=https;AccountName=mydagsterpocstg;AccountKey=Ba187/pVE8XW9bc+xs9leOxB7534CIQebRchQJzTP7zKA07OJPVAovz+CE7WISTiMf5+iDWqiIOo+AStaWTc0Q==;EndpointSuffix=core.windows.net"
account_url="https://mydagsterpocstg.blob.core.windows.net/"
import pandas as pd

service = ShareServiceClient.from_connection_string(
    conn_str=ConnectionString
)

client = service.get_share_client(share='mypocfs')
file_client = client.get_file_client(file_path='poc/fileshare-poc.csv')
df = pd.DataFrame({"column1": [1, 2, 3], "column2": ["A", "B", "C"]})

csv_data = df.to_csv(index=False)
file_client.upload_file(csv_data)


