from storage import b2_client, B2_BUCKET_NAME


try:
    response = b2_client.list_objects_v2(
        Bucket=B2_BUCKET_NAME,
        MaxKeys=5
    )

    print("====================================")
    print("Backblaze B2 connection successful!")
    print("Bucket:", B2_BUCKET_NAME)
    print("====================================")

    objects = response.get("Contents", [])

    if objects:
        print("Existing objects:")
        for obj in objects:
            print("-", obj["Key"])
    else:
        print("Bucket is currently empty.")

except Exception as e:
    print("====================================")
    print("Backblaze B2 connection FAILED")
    print("====================================")
    print("Error:", e)